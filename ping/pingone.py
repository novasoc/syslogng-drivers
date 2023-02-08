"""
Copyright (c) 2023 novaSOC

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.

Original development by Dan Elder (delder@novacoast.com)

Syslog-ng python source for PingOne Admin API
https://admin-api.pingone.com/v3-beta/api-docs/

Additional documentation available at:
https://www.syslog-ng.com/technical-documents/doc/syslog-ng-open-source-edition/3.36/administration-guide/25#TOPIC-1768580
"""

from json.decoder import JSONDecodeError
from datetime import datetime
import os
import json
import logging
import requests

import syslogng

class PingAdmin(syslogng.LogFetcher):
    """
    Class for python syslog-ng fetch-style log source
    """

    # Initialize PingAdmin driver
    def init(self, options):
        """
        Initialize PingAdmin driver options
        (optional for Python LogFetcher)
        """

        # Initialize logger for driver
        self.logger = logging.getLogger('PingOne Admin')
        stream_logger = logging.StreamHandler()

        # Standard log format
        log_format = " - ".join((
            "Ping Admin Driver",
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

        # Initialize empty list of log messages
        self.logs = []

        # Ensure client_id parameter is defined
        if "client_id" in options:
            self.client_id = options["client_id"]
            self.logger.debug("Initializing Ping API with client_id %s", self.client_id)
        else:
            self.logger.error("Missing client_id configuration option")
            self.exit = True
            return False

        # Ensure client_secret parameter is defined
        if "client_secret" in options:
            self.client_secret = options["client_secret"]
            self.logger.debug("Initializing Ping API with client_secret %s", self.client_secret)
        else:
            self.logger.error("Missing client_secret configuration option")
            self.exit = True
            return False

        # Ensure accountId parameter is defined
        if "accountId" in options:
            self.accountId = options["accountId"]
            self.logger.debug("Initializing Ping API with accountId %s", self.accountId)
        else:
            self.logger.error("Missing accountId configuration option")
            self.exit = True
            return False

        # Ensure client_id parameter is defined
        if "id" in options:
            self.id = options["id"]
            self.logger.debug("Initializing Ping API with id %s", self.id)
        else:
            self.logger.error("Missing id configuration option")
            self.exit = True
            return False

        # Use disk buffer if configured
        if "disk_buffer" in options:
            self.buffer = options["disk_buffer"]
            self.logger.debug("Will use %s as disk buffer", self.buffer)

            # Read in the contents of the existing buffer to memory if there are any
            try:
                filebuffer = open(self.buffer, 'r', encoding="UTF-8")
                lines = filebuffer.readlines()
                # Convert each line in input buffer to json
                for line in lines:
                    try:
                        self.logs.append(json.loads(line))
                    except JSONDecodeError:
                        self.logger.warning("Unable to process %s from buffer", line)

                filebuffer.close()

                self.logger.info("Loaded %i events from disk buffer %s", len(self.logs), self.buffer)

                # Delete the buffer after it's been loaded into memory
                try:
                    os.remove(self.buffer)

                except Exception as e:
                    self.logger.error("Unable to delete buffer %s", self.buffer)
                    self.logger.error(str(e))
                    return False

            except FileNotFoundError:
                self.logger.warning("Buffer file %s does not exist", self.buffer)

            except Exception as e:
                self.logger.warning("Unable to read buffer %s", self.buffer)
                self.logger.warning(str(e))

        return True


    def process_message(self, log):
        """
        Parse a single log message and extrace timestamp and program field
        """

        message = log

        # Logs should be in json format
        try:
            message = str(json.dumps(log))
        except JSONDecodeError:
            self.logger.warning("Unable to decode log as json: %s", log)
        except Exception as ex:
            self.logger.error("Error processing %s : %s", log, ex)

        # Set static program field
        msg = syslogng.LogMessage(message)
        msg["PROGRAM"] = "PINGID"

        # Set dynamic program field if available
        if "source" in log:
            try:
                msg["PROGRAM"] = log['source']
            except Exception:
                self.logger.warning("Unable to extract source from %s", log)

        # Extract timestamp from recorded field and set as syslog timestamp
        if "recorded" in log:
            try:
                timestamp = datetime.strptime(log['recorded'], "%Y-%m-%dT%H:%M:%S.%f%z")
                msg.set_timestamp(timestamp)
            except Exception as ex:
                self.logger.debug("Unable to convert %s to timestamp : %s", \
                    log['recorded'], ex)

        return msg


    def fetch(self):
        """
        Return a single log message by either pulling from the internal dict or pulling from the Ping API
        """

        # Retrieve log messages from memory if present
        if len(self.logs) > 0:
            try:
                log = self.logs.pop(0)
                msg = self.process_message(log)
                return syslogng.LogFetcher.FETCH_SUCCESS, msg
            except Exception as ex:
                self.logger.error("Error processing in memory log : %s", ex)

        # Retrieve log messages from Ping API
        subscription_url = "https://admin-api.pingone.com/v3/reports/%s/poll-subscriptions/%s/events" \
            % (self.accountId, self.id)
        headers =  {"Content-Type":"application/x-www-form-urlencoded", "Accept":"application/json", \
            "Authorization": "Bearer %s" % self.auth_token}

        try:
            response = requests.get(subscription_url, headers=headers)

            # Ingore 504 errors which seem to be common with Ping
            if response.status_code == 504:
                self.logger.info("Gateway Timeout from Ping")
                return syslogng.LogFetcher.FETCH_TRY_AGAIN, "Gateway Timeout from Ping"

            # If this isn't a 504 error
            else:
                # If the API call returns successfully, parse the retrieved json data
                if response.status_code == 200:
                    self.logs = response.json()
                    self.logger.debug("Retrieved %i messages from Ping API fetch", len(self.logs))

                    # If there are new logs
                    if self.logs:

                        # Process first message from retrieved events
                        log = self.logs.pop(0)
                        msg = self.process_message(log)
                        return syslogng.LogFetcher.FETCH_SUCCESS, msg

                    # If there aren't new logs
                    else:
                        return syslogng.LogFetcher.FETCH_NO_DATA, "No new Ping events available"

                # If the auth token has expired
                if response.status_code == 403:
                    self.logger.info("Auth token expired (this normally happens roughly once an hour)")
                    return syslogng.LogFetcher.FETCH_ERROR, "Ping API auth token expired or invalid - %s", response.text

                # If the response code isn't 504 or 200 (or isn't even set)
                else:
                    self.logger.warning("Failed to retrieve events from %s : HTTP response code is %s", \
                        subscription_url, response.status_code)
                    self.logger.debug("Header values sent were %s", headers)
                    self.logger.warning("Server response was %s", response.json())
                    return syslogng.LogFetcher.FETCH_ERROR, "Ping API access failure %s", response.text

        except Exception as ex:
            self.logger.error("Error accessing %s : %s", subscription_url, ex)
            return syslogng.LogFetcher.FETCH_ERROR, "Error accessing %s : %s", subscription_url, ex


    def request_exit(self):
        """
        Begin shutdown process for driver
        """

        self.logger.info("Shutdown requested with %i events in memory buffer", len(self.logs))
        self.close()
        self.exit = True


    def open(self):
        """
        Retrieve auth token for Ping API
        """

        self.logger.info("Retreiving auth token for Ping API")

        # Retrieve auth token from Ping
        auth_url = "https://admin-api.pingone.com/latest/as/token.oauth2?client_id=%s&client_secret=%s&grant_type=client_credentials" % (self.client_id, self.client_secret)
        headers =  {"Content-Type":"application/x-www-form-urlencoded", "Accept":"application/json"}
        response = requests.post(auth_url, headers=headers)

        # Handle error condition of invalid auth attempt
        if response.status_code != 200:
            self.logger.warning("Failed to authenticate to Ping : HTTP response code is %s", response.status_code)
            self.logger.debug("Server responded with %s", response.json())
            return False

        # Extract and set auth_token for use by other API calls
        self.auth_token = response.json()['access_token']
        self.logger.debug("Auth token is %s", self.auth_token)
        return True


    def close(self):
        """
        Revoke Ping auth token
        """

        self.logger.info("Revoking Ping API auth token")

        # Revoke authentication token from Ping API
        auth_url = "https://admin-api.pingone.com/latest/as/revoke_token.oauth2?client_id=%s&token=%s" \
            % (self.client_id, self.auth_token)
        headers =  {"Content-Type":"application/x-www-form-urlencoded", "Accept":"application/json"}
        response = requests.post(auth_url, headers=headers)

        # If there is a failure revoking the token
        if response.status_code != 200:
            self.logger.warning("Unable to revoke Ping API auth token")
            self.logger.info("HTTP response code is %s", response.status_code)
            self.logger.info("Response is %s", response.json())
            return False
        return True


    def deinit(self):
        """
        Flush in-memory logs to buffer file if configured during shutdown
        """

        self.logger.info("Deinitializing with %i events in memory buffer", len(self.logs))

        # If there are events still in memory
        if self.logs:

            # Check if disk buffer is configured
            try:
                self.buffer

                # Flush memory buffer to disk buffer
                self.logger.info("Flushing %i events to disk buffer %s", \
                    len(self.logs), self.buffer)

                try:
                    with open(self.buffer, 'a') as filebuffer:

                        # Loop through every entry in self.logs and delete as we go
                        while self.logs:
                            message = json.dumps(self.logs.pop(0))
                            filebuffer.write(message + '\n')

                # Write to file buffer error
                except IOError as e:
                    self.logger.error("Unable to flush memory to disk buffer at %s", self.buffer)
                    self.logger.error(str(e))

                # Catch general exception
                except Exception as e:
                    self.logger.error(str(e))
                    return False

            # Warn that events will be lost because no file buffer is present
            except NameError:
                self.logger.error("Closing connection but %i events may be lost in memory buffer", len(self.logs))
                self.logger.error("Please configure the disk_buffer option in the future to prevent loss of Ping events")

        # No events in memory, ready for clean shutdown
        else:
            self.logger.info("No events to flush from memory")
