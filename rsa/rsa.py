"""
Copyright (c) 2022 novaSOC

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.

Original development by Dan Elder (delder@novacoast.com)
Syslog-ng python fetcher for RSA SecurID Cloud
(https://community.securid.com/t5/securid-cloud-authentication/cloud-administration-user-event-log-api/ta-p/623082)

Additional documentation available at:
https://www.syslog-ng.com/technical-documents/doc/syslog-ng-open-source-edition/3.36/administration-guide/26#TOPIC-1768583
"""

import json
import logging
import re
from datetime import datetime, timedelta
import time
import sys
import requests
import jwt
import syslogng

class SecurIDCloud(syslogng.LogFetcher):
    """
    class for python syslog-ng log fetcher
    """

    def init(self, options):
        """
        Initialize SecurID Cloud driver
        (optional for Python LogFetcher)
        """

        # Only admin and user log types are supported
        if "log_type" in options:
            if options["log_type"].lower() == "admin":
                self.log_type = "admin"
                self.url2 = "/AdminInterface/restapi/v1/adminlog/exportlogs"
                self.entry_name = "elements"
            elif options["log_type"].lower() == "user":
                self.log_type = "user"
                self.url2 = "/AdminInterface/restapi/v1/usereventlog/exportlogs"
                self.entry_name = "userEventLogExportEntries"
        else:
            print("Missing or invalid log_type, defaulting to admin")
            self.log_type = "admin"
            self.url2 = "/AdminInterface/restapi/v1/adminlog/exportlogs"
            self.entry_name = "elements"

        # Initialize logger for driver
        self.logger = logging.getLogger('SecurID Cloud ' + self.log_type)
        stream_logger = logging.StreamHandler()

        # Standard log format
        log_format = " - ".join((
            "SecurID Cloud %s" % self.log_type,
            "%(levelname)s",
            "%(message)s"
        ))

        # Configure logging for standard log format
        formatter = logging.Formatter(log_format)
        stream_logger.setFormatter(formatter)
        self.logger.addHandler(stream_logger)

        # Check for valid log level and set loggers
        if "log_level" in options:
            if options["log_level"].upper() == "DEBUG":
                self.logger.setLevel(logging.DEBUG)
            elif options["log_level"].upper() == "INFO":
                self.logger.setLevel(logging.INFO)
            elif options["log_level"].upper() == "WARN":
                self.logger.setLevel(logging.WARNING)
            elif options["log_level"].upper() == "ERROR":
                self.logger.setLevel(logging.ERROR)
            elif options["log_level"].upper() == "CRIT":
                self.logger.setLevel(logging.CRITICAL)
        else:
            self.logger.setLevel(logging.INFO)
            self.logger.warning("Invalid or no log level specified, setting log level to INFO")

        self.logger.info("Starting RSA SecurID Cloud API fetch driver for %s", self.log_type)

        # jwt module not included with syslog-ng PE so path modification is needed
        self.logger.debug("Python module path is %s", sys.path)

        # Initialize empty array of log messages
        self.logs = []

        # Whether to use last search window end time or ignore it
        ignore_persistence = False
        if "ignore_persistence" in options:
            if options["ignore_persistence"].lower() == "true":
                ignore_persistence = True
                self.logger.info("Disabling persistence for initial fetch window")

        # Ensure url parameter is defined
        if "url" in options:
            self.url = options["url"]
            self.logger.info("Initializing driver against URL %s", self.url)
        else:
            self.logger.error("Missing url configuration option for %s", self.log_type)
            self.exit = True
            return False

        # Ensure RSA SecurID key path is set
        if "rsa_key" in options:
            self.rsa_key = options["rsa_key"]
            self.logger.debug("Initializing driver with rsa_key %s for %s", \
                self.rsa_key, self.log_type)
        else:
            self.logger.error("Missing rsa_key path configuration option for %s", self.log_type)
            self.exit = True
            return False

        # Set page size if defined
        self.page_size = 100
        if "page_size" in options:
            self.page_size = options["page_size"]
            self.logger.info("Initializing driver with pageSize %s for %s" \
                , self.page_size, self.log_type)

        # Set ssl_verify to false only if specified
        self.ssl_verify = True
        if "ssl_verify" in options:
            if options["ssl_verify"].lower() == "false":
                self.ssl_verify = False
                self.logger.info("Disabling SSL certificate verification for ssl_verify")

        # Set max_performance if defined
        self.max_performance = False
        if "max_performance" in options:
            if options["max_performance"].lower() == "true":
                self.max_performance = True
                self.logger.info("Disabling parsing json messages and timestamps for maximum performance")

        # Default time to go back is 4 hours
        initial_hours = 4
        if "initial_hours" in options:

            # Extract decimal value from initial_hours setting
            try:
                initial_hours = int(re.search(r'\s*(\d+)\s*', options["initial_hours"]).group(1))
            except Exception as ex:
                self.logger.error("Invalid value (%s) for initial_hours : %s", options["initial_hours"], ex)

            self.logger.info("Initializing driver with initial_hours %i hours ago for %s" \
                , initial_hours, self.log_type)

        # Set delta for initial_hours back in time
        default_start_time = timedelta(hours = initial_hours)

        # Get the current datetime in UTC to avoid timezone fun
        self.start_time = self.to_rsa_timestamp(datetime.utcnow())

        # Setup persist_name with defined persist_name or use URL and log_type if none specified
        try:
            self.persist_name
        except:
            self.persist_name = "rsa-securid-cloud-%s-%s" % (self.url, self.log_type)

        # Initialize persistence
        self.logger.debug("Initializing driver with persist_name %s", \
                self.persist_name)
        self.persist = syslogng.Persist(persist_name=self.persist_name, defaults={"last_read": self.start_time})

        # Ignore persistence if configured
        if ignore_persistence:
            self.logger.info("Ignoring persistence file and initializing for %i hour initial search window", initial_hours)
            self.start_time = self.to_rsa_timestamp(datetime.utcnow() - default_start_time)
        else:
            # Start search at last fetch window end time
            try:
                self.logger.debug("Persistence was set to %s", self.persist["last_read"])

                # Ensure the last_read time is a valid datetime format
                valid_datetime = datetime.strptime(self.persist["last_read"], "%Y-%m-%dT%H:%M:%S.%f%z")
                self.start_time = self.persist["last_read"]
            except:
                # If last_read isn't valid, reset to initial_hours ago
                self.logger.error("Invalid last_read (%s) detected in persistence, resetting to %s hours ago", \
                    self.persist["last_read"], initial_hours)
                self.start_time = self.to_rsa_timestamp(datetime.utcnow() - default_start_time)

        self.logger.info("Driver initialization complete, fetch window starts at %s", \
            self.start_time)

        return True


    def fetch(self):
        """
        Return a log message by pulling from the internal list or pulling from the RSA SecurID Cloud API
        (mandatory function for Python LogFetcher)
        """

        # Retrieve log messages from memory if present
        if self.logs:
            log = self.logs.pop(0)
            msg = self.parse_log(log)
            return syslogng.LogFetcher.FETCH_SUCCESS, msg

        # Get current datetime
        self.end_time = self.to_rsa_timestamp(datetime.utcnow())

        # UTL to retrieve log messages from RSA SecurID Cloud API
        subscription_url = self.url + self.url2 + \
            "?startTimeAfter=" + self.start_time + \
                "&endTimeOnOrBefore=" + self.end_time + \
                    "&pageSize=" + str(self.page_size)

        # Headers for request
        headers =  {"Content-Type":"application/application-json", \
            "Accept":"application/json", "Authorization": "Bearer %s" \
            % self.bearer_token}

        # Perform HTTP request
        response = requests.get(subscription_url, headers=headers)

        # Ingore 504 errors
        if response.status_code == 504:
            self.logger.info("Gateway Timeout from RSA SecurID Cloud")
            return syslogng.LogFetcher.FETCH_TRY_AGAIN, "Gateway Timeout"

        # Ingore 400 errors
        if response.status_code == 400:
            self.logger.info("Bad Error Request : %s", subscription_url)
            return syslogng.LogFetcher.FETCH_ERROR, "Bad Request"

        # If the API call returns successfully, parse the retrieved json data
        if response.status_code == 200:

            try:
                result = response.json()
                total_records = result['totalElements']
                total_pages = result['totalPages']
                current_page = result['currentPage']

                # Set internal log buffer to all returned events
                self.logs = result[self.entry_name]
                self.logger.debug("%i events available", total_records)

            except Exception as e_all:
                return syslogng.LogFetcher.FETCH_ERROR, "%s - access failure : %s\n%s", \
                    self.url, e_all, response.text

            # If there are more pages of events to process
            while current_page < total_pages:

                # increment page counter
                current_page = current_page + 1

                # URL to retrieve log messages from RSA SecurID Cloud API
                subscription_url = self.url + self.url2 + \
                    "?startTimeAfter=" + self.start_time + \
                        "&endTimeOnOrBefore=" + self.end_time + \
                            "&pageSize=" + str(self.page_size) + \
                                "&pageNumber=" + str(current_page)

                headers =  {"Content-Type":"application/application-json", \
                    "Accept":"application/json", "Authorization": "Bearer %s" \
                    % self.bearer_token}

                # Perform HTTP request
                response = requests.get(subscription_url, headers=headers)

                # If we're successful, parse the json result
                if response.status_code == 200:
                    try:
                        result = response.json()
                    except Exception as e_all:
                        return syslogng.LogFetcher.FETCH_ERROR, "%s - access failure : %s\n%s", \
                            self.url, e_all, response.text

                    # Add each event to our internal logs list
                    for entry in result[self.entry_name]:
                        self.logs.append(entry)

                # If something went wrong with the query
                else:
                    return syslogng.LogFetcher.FETCH_ERROR, "%s - %s access failure:\n%s", \
                        self.url, self.log_type, response.text

            # Set start time to end time
            self.start_time = self.end_time

            # If there are new logs
            if self.logs:

                # Process each log message
                log = self.logs.pop(0)
                msg = self.parse_log(log)
                return syslogng.LogFetcher.FETCH_SUCCESS, msg

            # If there aren't new logs
            self.persist["last_read"] = self.end_time
            return syslogng.LogFetcher.FETCH_NO_DATA, "No new events available"

        # If the bearer token is invalid
        if response.status_code == 403:
            self.logger.error("Bearer token invalid or expired")
            return syslogng.LogFetcher.FETCH_ERROR, "bearer token expired or invalid"

        # If the response code isn't 504 or 200 (or isn't even set)
        return syslogng.LogFetcher.FETCH_ERROR, "%s - access failure:\n%s", \
            self.url, response.text


    def open(self):
        """
        Retrieve bearer token for RSA SecurID Cloud
        (optional for Python LogFetcher)
        """

        # Auth token is needed for all API requests
        self.logger.info("Retreiving bearer token for RSA SecurID Cloud for %s", self.log_type)
        self.bearer_token = self.generate_token()

        # Critical failure if we're unable to generate an auth token
        if self.bearer_token is False:
            self.logger.error("Unable to acquire auth token")
            return False

        return True


    def deinit(self):
        """
        Driver de-initialization routine
        (optional for Python LogFetcher)
        """

        # Only update persistence if all logs in memory were processed
        if len(self.logs) > 0:
            self.logger.warning("Deinitializing with %i %s events in memory buffer", \
                len(self.logs), self.log_type)
        else:
            self.persist["last_read"] = self.end_time


    def to_rsa_timestamp(self, stamp):
        """
        Converts a datetime object to a string format used by RSA SecurID Cloud
        """

        tseconds = int(int(stamp.strftime("%f")) / 1000)
        timestamp = stamp.strftime("%Y-%m-%dT%H:%M:%S.") + str(tseconds) + "-00:00"
        return timestamp


    def parse_log(self, log):
        """
        Parse an event into a syslog LogMessage
        (custom function for message parsing)
        """

        # Create syslogng LogMessage and set PROGRAM
        msg = syslogng.LogMessage(str(json.dumps(log)))
        program = "RSA SecurID Cloud " + self.log_type.capitalize()
        msg["PROGRAM"] = program.replace(" ", "-")

        # Do not parse message as json for higher performance if set
        if self.max_performance is True:
            return msg

        # If performance isn't an issue (and it shouldn't be)
        else:

            # Try to get timestamp information from message
            if "eventLogDate" in log:
                try:
                    timestamp = datetime.strptime(log['eventLogDate'], "%Y-%m-%dT%H:%M:%S.%f%z")
                    msg.set_timestamp(timestamp)

                except Exception as e_all:
                    self.logger.debug("Unable to convert %s to timestamp for %s : %s", \
                        log['eventLogDate'], self.log_type, e_all)

            # Return LogMessage
            return msg


    def parse_key(self):
        """
        Parse the contents of the RSA SecurID Cloud Admin API key file
        """

        # Open key and verify all required values are set
        try:
            with open(self.rsa_key, "r") as keyFile:
                key = json.load(keyFile)
                if "adminRestApiUrl" not in key:
                    self.logger.error("Failed to parse adminRestApiUrl from the RSA SecurID Cloud Admin API key")
                    self.exit = True
                    return False
                if "accessID" not in key:
                    self.logger.error("Failed to parse accessID from the RSA SecurID Cloud Admin API key")
                    self.exit = True
                    return False
                if "accessKey" not in key:
                    self.logger.error("Failed to parse accessKey from the RSA SecurID Cloud Admin API key")
                    self.exit = True
                    return False
                return key

        except IOError as e:
                self.logger.error("Encountered error attempting to parse the RSA SecurID Cloud Admin API key: '{0}'\n".format(self.rsa_key))
                self.logger.info(str(e) + "\n")
                self.exit = True
                return False


    def generate_token(self):
        """
        Generate JWT token based off Admin API key file
        """

        # Get contents of key as dict
        key = self.parse_key()

        # Initialize to the max valid period for a jwt of 60 minutes
        exp = time.time() + 60 * 60

        # Build out jwt claim for auth token
        jwt_claims = {
            "iat": time.time(), # Set issued at time to the current time.
            "exp": exp, # Set expiration time
            "aud": key["adminRestApiUrl"],  # Audience of the claim.
            "sub": key["accessID"], # Access ID from the Admin API Key.
        }

        # Use the accessKey from the Admin API key file and the RS256 algorithm to generate the JWT
        try:
            jwt_token = jwt.encode(
                payload=jwt_claims,
                key=key["accessKey"],
                algorithm="RS256"
            )
        except Exception as ex:
            self.logger.error("Unable to generate jwt token from %s : %s", self.rsa_key, ex)

        return jwt_token
