"""
Copyright (c) 2022 novaSOC

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.

Original development by Dan Elder (delder@novacoast.com)
Syslog-ng Python fetcher for Symantec WSS Sync API (https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/web-security-service/help/wss-api/report-sync-about.html)

Additional documentation available at:
https://www.syslog-ng.com/technical-documents/doc/syslog-ng-open-source-edition/3.36/administration-guide/26#TOPIC-1768583
"""

import logging
import base64
import re
import os
from datetime import datetime, timezone, timedelta
import socket
import zipfile
import gzip
import requests
import pytz

import syslogng

class WSS(syslogng.LogFetcher):
    """
    class for python syslog-ng log fetcher
    """

    def init(self, options):
        """
        Initialize Symantec WSS driver
        (optional for Python LogFetcher)
        """

        # Initialize logger for driver
        self.logger = logging.getLogger('Symantec-WSS')
        stream_logger = logging.StreamHandler()

        # Standard log format
        log_format = " - ".join((
            "Symantec-WSS",
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

        self.logger.debug("Starting Symantec WSS fetch driver")

        # Non-syslog-ng configurable defaults
        self.separator = "|"
        self.quote_value = True

        # Sleep lock
        self.sleep = False

        # Initialize empty array of log messages
        self.logs = []

        # Empty list of keys for value mapping
        self.keys = []

        # Initialize URL
        self.url = "https://portal.threatpulse.com/reportpod/logs/sync"

        # Ensure username parameter is defined
        if "username" in options:
            self.username = options["username"]
        else:
            self.logger.error("Missing username for WSS driver")
            return False

        # Ensure password parameter is defined
        if "password" in options:
            self.password = options["password"]

            # base64 decode self.password and convert to usable self.clear_password
            try:
                self.clear_password = base64.b64decode(self.password).decode("utf-8")
            except Exception as e_all:
                print("Unable to decode password %s : %s", self.password, e_all)
                return False
        else:
            self.logger.error("No password configured for WSS driver")
            return False

        # Set temp directory if defined
        self.buffer_dir = "/tmp"
        if "buffer_dir" in options:
            self.logger.debug("Buffer directory set to %s", self.buffer_dir)
            self.buffer_dir = options["buffer_dir"]
            self.buffer_path = self.buffer_dir + "/buffer"
            self.buffer_tmp = self.buffer_dir + "/tmp"

            # Create subdirectories as needed
            try:
                os.makedirs(self.buffer_path, 0o700, exist_ok=True)
                os.makedirs(self.buffer_tmp, 0o700, exist_ok=True)
            except Exception as ex:
                self.logger.error("Unable to create directories under %s : %s", self.buffer_dir, ex)
                return False

            # Ensure directories are writable
            try:
                with open(self.buffer_dir + "/test", 'w'):
                    pass
                os.remove(self.buffer_dir + "/test")
                with open(self.buffer_path + "/test", 'w'):
                    pass
                os.remove(self.buffer_path + "/test")
                with open(self.buffer_tmp + "/test", 'w'):
                    pass
                os.remove(self.buffer_tmp + "/test")
            except Exception as ex:
                self.logger.error("Write failures to buffer directories : %s", ex)
                return False

        # Option to extract hostname from logs
        self.extract_hostnames = True
        if "extract_hostnames" in options:
            if options["extract_hostnames"].lower() == "false":
                self.extract_hostnames = False
                self.logger.info("Hostnames will not be extracted from events")

        # Option to convert entries to key-value pairs
        self.key_values = True
        if "key_values" in options:
            if options["key_values"].lower() == "false":
                self.key_values = False
                self.logger.info("Key-value pairs will not be parsed from events")

        # Default time to go back is 0 hours on first run
        self.initial_hours = 0
        if "initial_hours" in options:

            # Extract integer value from initial_hours setting
            try:
                self.initial_hours = int(re.search(r'.*?(\d+).*', options["initial_hours"]).group(1))
            except Exception as ex:
                self.logger.error("Invalid value (%s) for initial_hours : %s", options["initial_hours"], ex)

            self.logger.debug("Initializing Symantec WSS syslog-ng driver with initial_hours %i" \
                , self.initial_hours)

        # Default timeout for downloads
        self.timeout = 900
        if "timeout" in options:

            # Extract decimal value from timeout setting
            try:
                self.timeout = int(re.search(r'.*?(\d+).*', options["timeout"]).group(1))
            except Exception as ex:
                self.logger.error("Invalid value (%s) for timeout : %s", options["timeout"], ex)

            self.logger.debug("Initializing Symantec WSS syslog-ng driver with timeout %i" \
                , self.initial_hours)

        # Setup persist_name with defined persist_name or use symteac-wss if none specified
        try:
            self.persist_name
        except:
            self.persist_name = "symantec-wss"

        # Check for first run/empty sync_token
        self.sync_token = "none"

        # Initialize persistence
        self.logger.debug("Initializing Symantec WSS syslog-ng driver with persist_name %s", \
                self.persist_name)
        self.persist = syslogng.Persist(persist_name=self.persist_name, defaults={"sync_token": self.sync_token})

        # Check for first run/empty sync_token
        try:
            self.sync_token = self.persist["sync_token"]
            self.logger.debug("Previous sync_token from persistence is %s", self.sync_token)
        except Exception as ex:
            self.logger.warning("Invalid sync_token in persistence, ignoring it")
            self.sync_token = "none"

        # Default time to go back is 0 hours on first run
        self.initial_hours = 0
        if "initial_hours" in options:

            # Extract integer value from initial_hours setting
            try:
                self.initial_hours = int(re.search(r'.*?(\d+).*', options["initial_hours"]).group(1))
                # ignore sync_token since we're starting from a new fetch window
                if self.initial_hours > 0:
                    self.sync_token = "none"
            except Exception as ex:
                self.logger.error("Invalid value (%s) for initial_hours : %s", options["initial_hours"], ex)

            self.logger.debug("Initializing Symantec WSS syslog-ng driver with initial_hours %i" \
                , self.initial_hours)

        # Path to buffer file
        self.buffer_file = self.buffer_path + "/WSS-buffer.data"

        # Path to keys mapping file (if used)
        self.keys_file = self.buffer_path + "/WSS.keys"

        # If we're fetching historical logs, ignore buffer and delete it
        if self.initial_hours > 0:
            try:
                os.remove(self.buffer_file)
            except Exception as ex:
                self.logger.error("Unable to delete buffer file (%s) : %s", \
                    self.buffer_file, ex)

        # Read events from buffer file if present into in-memory logs
        if os.path.isfile(self.buffer_file):

            # Open buffer and read in events
            try:
                buffer = open(self.buffer_file, "r")
                self.logs = buffer.readlines()
                buffer.close()

                # Delete file after processing
                try:
                    os.remove(self.buffer_file)
                except Exception as ex:
                    self.logger.error("Unable to delete buffer file (%s) so ignoring %i entries from it : %s", \
                        self.buffer_file, len(self.logs), ex)
                    self.logs.clear()

                # Last line in buffer should be token from last run
                if self.logs:
                    token = ""
                    token = self.logs.pop()

                    # Check for valid token line
                    result = re.match(r'^\D+$', token)
                    if result:
                        self.sync_token = token
                        self.logger.info("Valid buffer file (%s) loaded with %i entries ending at token %s", \
                            self.buffer_file, len(self.logs), self.sync_token)
                    else:
                        self.logger.warning("Invalid buffer file, discarding %i lines from %s", len(self.logs), \
                            self.buffer_file)
                        self.logs.clear()

                # If we're supposed to parse kv pairs and we imported logs
                if self.key_values and self.logs:
                    # Read events from keys file if present for key-value mappings
                    try:
                        keys_file = open(self.keys_file, "r")
                        self.keys = keys_file.readline().rstrip().split(',')
                        keys_file.close()
                        if len(self.keys) > 1:
                            self.logger.debug("Successfully imported key mapping: %s", self.keys)
                        else:
                            self.logger.error("No key mappings found in %s", self.keys_file)
                            self.logger.warning("%i events will be processed without key value mapping", len(self.logs))

                    except Exception as ex:
                        self.logger.error("Error reading key mappings %s : %s", self.keys_file, ex)
                        self.logger.warning("%i events will be processed without key value mapping", len(self.logs))

                    # Cleanups keys_file if it exists
                    if os.path.isfile(self.keys_file):
                        try:
                            os.remove(self.keys_file)
                        except Exception as ex:
                            self.logger.error("Unable to delete keys file %s : %s", self.keys_file, ex)

            except Exception as ex:
                self.logger.warning("Unable to access buffer file %s : %s",self.buffer_file, ex )

        # No buffer file exists
        else:
            self.logger.debug("No buffer file detected, assuming previous shutdown was clean")

        return True


    def parse_log(self, log):
        """
        Parse an event into a syslog LogMessage or string syslog format
        (custom function for message parsing)
        """

        # Cleanup trailing newlines
        log = log.rstrip()

        # Set defaults
        program = "Symantec-WSS"
        host = socket.gethostname()
        utc = datetime.utcnow()

        # Extract timestamp and hostname from event if possible
        try:
            if self.extract_hostnames:
                result = re.search(r"^\d+\s(\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)\s\"(.+?)\"", log)
                host = result.group(2)
            else:
                result = re.search(r"^\d+\s(\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)", log)
            datestamp = datetime.strptime(result.group(1), "%Y-%m-%d %H:%M:%S")
            utc = datestamp.astimezone(pytz.timezone('UTC'))

        except Exception as ex:
            self.logger.debug("Invalid WSS format: %s (%s)", log, ex)

        # Convert message to key-value pairs
        if self.key_values and len(self.keys) > 1:
            log = self.kv_extract(log)

        # Format message as LogMessage object
        msg = syslogng.LogMessage(log)
        msg.set_timestamp(utc)
        msg["HOST"] = host
        msg["PROGRAM"] = program
        return msg


    def kv_extract(self, log):
        """
        Convert a Symantec WSS log into key=value format
        """

        counter = 0
        entry = ""
        try:
            # Split content by quotes and whitespace
            values = self.format_string_to_array(log)

            # Ensure we have the correct number of keys and values
            if len(self.keys) != len(values):
                self.logger.error("%i keys != %i values for %s", len(self.keys), len(values), log)
                return log

            # Loop through every key-value pair
            while counter < len(values):

                # Include separator as needed
                if counter > 0:
                    entry = entry + self.separator

                # Assign empty values to keys but convert them first
                if values[counter] == "-":
                    values[counter] = ""

                # Add key-value to entry (check for existing double quotes)
                if self.quote_value:
                    entry = entry + "\"%s\"=\"%s\"" % (self.keys[counter], values[counter].strip('"'))
                else:
                    entry = entry + "%s=%s" % (self.keys[counter], values[counter].strip('"'))

                counter = counter + 1

        except Exception as ex:
            self.logger.warning("Invalid entry for kv parsing %s (%s): %s", log, entry, ex)
            return log

        return entry


    def extract_logs(self, zip_archive):
        """
        Uncompress log archives and extract logs from them
        """

        try:
            # Open Zip archive
            with zipfile.ZipFile(zip_archive) as archive:
                for filename in archive.namelist():

                    # For every gzip archive inside the zip (should be everything in the zip)
                    if filename.endswith(".gz"):
                        self.gzip_archive = self.buffer_tmp + "/" + filename
                        archive.extract(filename, self.buffer_tmp + "/")
                        self.logger.debug("Extracted %s from %s under %s", filename, zip_archive, self.buffer_tmp)

                        # Extract the gzip archive for processing
                        with gzip.open(self.gzip_archive, 'rb') as log_archive:

                            # Process every line in file
                            for line in log_archive:
                                content = line.decode("utf-8")

                                # Ignore commented lines
                                if not content.startswith('#'):

                                    # Or add entry to in-memory logs
                                    self.logs.append(content)
                                
                                # Capture keys from header
                                else:
                                    header = re.search(r"^#Fields:\s(.+)", content)
                                    if header:
                                        keys = header.group(1).split()

                                        # Check if keys have changed
                                        if self.keys:
                                            if keys != self.keys:
                                                self.keys = keys
                                                self.logger.warning("Keys for value mapping in %s are new", self.gzip_archive)
                                        else:
                                            # Store globally for message parsing
                                            self.logger.debug("Initializing keys : %s", keys)
                                            self.keys = keys

                        # Cleanup gzip file
                        try:
                            os.remove(self.gzip_archive)
                        except Exception as ex:
                            self.logger.error("Unable to delete %s : %s", self.gzip_archive, ex)

        except Exception as ex:
            self.logger.error("Error extracting log archive %s: %s", zip_archive, ex)

        # Cleanup zip archive
        try:
            os.remove(zip_archive)
        except Exception as ex:
            self.logger.error("Unable to delete %s : %s", zip_archive, ex)

        # Report in-memory event count
        self.logger.debug("After processing %s there are %i log entries", zip_archive, len(self.logs))


    def fetch(self):
        """
        Return a log message by pulling from the internal list or pulling from Symantec WSS
        (mandatory function for Python LogFetcher)
        """

        # Wrap everything in a try/except to prevent syslog-ng issues
        try:
            # Retrieve log messages from memory if present
            if self.logs:
                log = self.logs.pop()
                msg = self.parse_log(log)
                return syslogng.LogFetcher.FETCH_SUCCESS, msg
            else:
                # No events are in memory so update sync_token
                self.persist["sync_token"] = self.sync_token

            # Trigger sleep (FETCH_NO_DATA condition) if needed to slow down client
            if self.sleep is True:
                self.sleep = False
                return syslogng.LogFetcher.FETCH_NO_DATA, "Backing off fetch to avoid overloading WSS"

            # Convert current time to milliseconds UTC since epoch
            now = datetime.now(timezone.utc)
            now_epoch = int(now.timestamp() * 1000)

            headers = {"X-APIUsername":"%s" % self.username, "X-APIPassword":"%s" % self.clear_password}

            # If we don't have a sync_token or initial_hours is > 0
            if self.sync_token == "none" or self.initial_hours > 0:

                # Get nearest hour in UTC rounded down for starting fetch window
                rounded_down = now.replace(second=0, microsecond=0, minute=0, hour=now.hour)

                # Start fetch window initial_hours back in time if set
                if self.initial_hours > 0:
                    self.logger.info("Starting fetch window %i hours back", self.initial_hours)
                    delta = timedelta(hours = self.initial_hours)
                    rounded_down = rounded_down - delta

                    # Make sure we don't go back initial_hours forever
                    self.initial_hours = 0

                self.logger.info("Starting fetch window at %s", rounded_down)

                # Convert to milliseconds since epoch
                start_time = int(rounded_down.timestamp() * 1000)

                # Construct URL for fetch using time based fetch window
                url = self.url + "?token=none&startDate=%s" % start_time + "&endDate=0"

            # Construct URL for fetch using sync_token to continue where last fetch left off
            else:
                self.logger.debug("Starting fetch from sync_token %s", self.sync_token)
                url = self.url + "?token=%s" % self.sync_token + "&startDate=0&endDate=0"

            # Downloaded zipfile location
            self.downloaded_archive = "%s/wss-%s.zip" % (self.buffer_tmp, now_epoch)

            try:
                # Perform HTTP request for streaming binary download of archive(s)
                with requests.get(url, headers=headers, stream=True, timeout=(10,self.timeout)) as self.response:

                    # Create local archive file as they are too large to store in memory
                    with open(self.downloaded_archive, "wb") as f:

                        # Download archive in chunks as they can be large
                        for chunk in self.response.iter_content(chunk_size=16*1024):
                            f.write(chunk)

            except Exception as ex:
                self.logger.error("Error during HTTP fetch of %s : %s", url, ex)
                return syslogng.LogFetcher.FETCH_ERROR, "HTTP error during fetch"

            # If archive was successfully downloaded
            if self.response.status_code == 200:

                # Open binary archive file to retrieve magic sync_token and status
                with open(self.downloaded_archive, "rb") as binary:

                    # Extract last 200 bytes of binary archive data
                    binary.seek(-250, 2)
                    output = binary.read(250)
                    clean = output.decode("utf-8", "replace")

                # Extract hidden sync_token and status from trailing archive data
                result = re.search(r"X-sync-token:\s+(\w+)\s+X-sync-status:\s+(\w+)", clean)
                if result:

                    # Get status if magic fields are present
                    sync_status = result.group(2)

                    # If the archive was constructed correctly and fetched completely
                    if sync_status == "done":

                        # Update sync_token for next fetch
                        self.sync_token = result.group(1)

                        self.logger.debug("Archive fully downloaded, sleeping before next fetch (%s)", self.sync_token)

                        # Extract log data
                        self.extract_logs(self.downloaded_archive)

                        # Wait an appropriate amount of time before fetching again
                        self.sleep = True

                    # If the archive was constructed correctly but more archives remain
                    elif sync_status == "more":

                        # Update sync_token for next fetch
                        self.sync_token = result.group(1)

                        self.logger.debug("Archive partially downloaded, will fetch remainder (%s)", self.sync_token)

                        # Extract log data
                        self.extract_logs(self.downloaded_archive)

                    # If something failed during the creation or download of the archive
                    else:
                        self.logger.error("Archive (%s) didn't download correctly (%s)", self.downloaded_archive, self.sync_token)
                        self.logger.error("Result is %s", sync_status)
                        if os.path.isfile(self.downloaded_archive):
                            try:
                                self.logger.debug("Cleaning up corrupt archive %s", self.downloaded_archive)
                                os.remove(self.downloaded_archive)
                            except Exception as ex:
                                self.logger.warning("Unable to delete %s : %s", self.downloaded_archive, ex)

                        return syslogng.LogFetcher.FETCH_ERROR, "Archive creation/download error"

                    # Handle new log messages from memory buffer if present
                    if self.logs:
                        log = self.logs.pop()
                        msg = self.parse_log(log)
                        return syslogng.LogFetcher.FETCH_SUCCESS, msg
                    else:
                        self.persist["sync_token"] = self.sync_token
                        return syslogng.LogFetcher.FETCH_NO_DATA, "No new events"

                # If we don't have an archive with magic sync-token and sync-status
                else:
                    self.logger.error("No sync-token or sync-status found in %s")
                    self.sleep = True
                    return syslogng.LogFetcher.FETCH_TRY_AGAIN, "Badly formatted archive"

            # Delay fetching due to too many WSS requests over a short period of time
            elif self.response.status_code == 429:

                self.logger.warning("Too many WSS queries over a short period of time")
                self.sleep = True
                return syslogng.LogFetcher.FETCH_NO_DATA, "Too many WSS queries over a short period of time"

            # sync_token is no longer valid, must fall back to date based fetches
            elif self.response.status_code == 410:

                self.logger.warning("Sync token is no longer valid, resetting to date based fetch")
                self.sync_token = "none"
                return syslogng.LogFetcher.FETCH_TRY_AGAIN, "Sync token is no longer valid, resetting to date based fetch"

            # Handle unknown responses
            else:
                self.logger.warning("Unknown response status (%s) : %s", self.response.status_code, self.response.text)
                self.sleep = True
                return syslogng.LogFetcher.FETCH_ERROR, "Unknown response status (%s) : %s" % (self.response.status_code, self.response.text)

        except Exception as ex:
            self.logger.error("Unknown error fetching new events : %s", ex)
            self.sleep = True
            return syslogng.LogFetcher.FETCH_ERROR, "Unknown error fetching new events : %s" % ex


    def open(self):
        """
        (optional for Python LogFetcher)
        """

        return True


    def close(self):
        """
        Close any open HTTP connections
        """
        try:
            self.response.close()
        except Exception as ex:
            self.logger.warning("Unable to close open HTTPS connection : %s", ex)


    def deinit(self):
        """
        Driver de-initialization
        """

        self.logger.info("Deinitializing driver")

        # Only update persistence if all logs in memory were processed
        if len(self.logs) > 0:
            self.logger.warning("Deinitializing with %i events in memory buffer", \
                len(self.logs))

            # Try to flush events to buffer file
            try:
                with open(self.buffer_file, "w") as buffer_file:
                    buffer_file.writelines(self.logs)

                    # Save sync_token as last line of buffer file
                    buffer_file.write(self.sync_token)
                    self.logger.info("Successfully flushed %i events to %s", len(self.logs), self.buffer_file)

            except Exception as ex:
                self.logger.error("Unable to save events to buffer (%s) file before shutdown: %s", self.buffer_file, ex)

            # Try to key mappings to keys_file
            try:
                keys_file = open(self.keys_file, 'w')
                joined_keys = ",".join(self.keys)
                print(joined_keys, file=keys_file)
                keys_file.close()

            except Exception as ex:
                self.logger.error("Unable to save key mappings to %s : %s", self.keys_file, ex)

        else:
            self.persist["sync_token"] = self.sync_token
            self.logger.info("Will resume fetch from sync_token %s on next run", self.sync_token)

        # Cleanup orphaned archives if present
        for file in os.listdir(self.buffer_tmp):
            try:
                os.remove(self.buffer_tmp + "/" + file)
                self.logger.info("Cleaning up orphaned archive %s", self.buffer_tmp + "/" + file)
            except Exception as ex:
                self.logger.error("Unable to remove %s : %s", self.buffer_tmp + "/" + file, ex)


    def request_exit(self): # mandatory
        """
        Cleanly shutdown driver
        """

        self.logger.info("Shutting down driver")

        # Interrupt http download if necessary
        try:
            self.response.close()
        except Exception as ex:
            self.logger.warning("Unable to close open HTTPS connection : %s", ex)


    def format_string_to_array(self, string):
        """
        Format a string with quotation marks but split by whitespace
        Significant performance increase over shlex
        Function developed by Krystal Tillman
        """

        array = []
        array_item = ""
        is_quote = False
        i = 0
        while i < len(string):
    
            if string[i:i+1] == " ":
                # Character is a space
                if is_quote == True:
                    # If quote, add character to array_string
                    array_item += string[i]
                elif is_quote == False:
                    # When word is finished
                    if not array_item == "":
                        # If array does not equal nothing, append
                        array.append(array_item)
                        array_item = ""
            elif string[i:i+1] == "\"":
                # Character is a quote
                if is_quote == False:
                    is_quote = True
                else:
                    array.append(array_item)
                    array_item = ""
                    is_quote = False
            else:
                # Character is normal
                array_item += string[i]

            i += 1
        array.append(array_item)
        return array
