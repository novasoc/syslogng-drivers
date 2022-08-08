"""
Copyright (c) 2022 novaSOC

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.

Original development by Dan Elder (delder@novacoast.com)

Syslog-ng python source for Proofpoint on Demand API
(https://community.microfocus.com/cyberres/arcsight/i/arcsightideas/proofpoint-on-demand-pod-cloud-api-development

Additional documentation available at:
https://www.syslog-ng.com/technical-documents/doc/syslog-ng-open-source-edition/3.36/administration-guide/25#TOPIC-1768580
"""

import logging
import base64
import ssl
import json
from datetime import datetime, timedelta
from time import sleep
import pytz
import websocket # websocket is not included in syslog-ng PE currently

from syslogng import LogSource
from syslogng import LogMessage

class ProofpointOnDemand(LogSource):
    """
    Class for python syslog-ng server-style log source
    """

    def on_close(self, wsapp, close_status_code, close_msg):
        """
        Handle websocket being closed by server
        """

        # Log closing information
        if close_status_code:
            self.logger.debug("Websocket closed status code: %s", str(close_status_code))
            try:
                if int(close_status_code) == 1000:
                    self.logger.info("Normal websocket shutdown")
                else:
                    self.logger.warning("Websocket error detected on shutdown (status code %s)", str(close_status_code))
            except Exception as ex:
                self.logger.warning("Unknown websocket status code (%s) : %s", close_status_code, ex)

        if close_msg:
            self.logger.debug("Websock closed message: %s", str(close_msg))

        if not close_status_code and not close_msg:
            self.logger.warning("Websocket shutdown without server feedback")


    def on_error(self, wsapp, error):
        """
        Error handling for websocket
        """

        # If the error has a status code, output common reasons
        try:
            if error.status_code == 400:
                self.logger.error("Bad Request : %s", error)
                self.logger.info("""Possible causes:
    Malformed URL query:
    - missing or empty clusterID
    - missing or empty message type
    - invalid sinceTime or toTime (if present)""")
                self.request_exit()
            elif error.status_code == 401:
                self.logger.error("Unauthorized : %s", error)
                self.logger.info("""Possible causes:
    - Missing or empty Authorization Header
    - Invalid type of access token
    - Missing or empty access token
    - Invalid or expired access token
    - Invalid clusterID
    - Missing or expired remote syslog license for the given clusterID""")
                self.request_exit()
            elif error.status_code == 404:
                self.logger.error("Not Found : %s", error)
                self.logger.info("""Possible causes:
    - Invalid URL
    - Invalid protocol (for example, http/https are not supported""")
                self.request_exit()
            elif error.status_code == 405:
                self.logger.error("Method not allowed : %s", error)
                self.logger.info("""Possible causes:
    - Client is sending non GET requests""")
                self.request_exit()
            elif error.status_code == 409:
                self.logger.error("Exceeded maximum number of sessions per token : %s", error)
                self.logger.info("""Possible causes:
    - The access token is being used by another session""")
                sleep(self.backoff_time)
            else:
                # If the status code isn't common
                self.logger.error("Unknown error in websocket : %s", error)

        except BrokenPipeError as BPE:
            self.logger.error("Broken websocket pipe detected : %s", BPE)

        # Catch all for unknown error type
        except Exception as ex:
            self.logger.warning("Error processing websocket : %s", error)
            self.logger.debug(ex)


    def on_message(self, wsapp, message):
        """
        Message handling for websocket
        """

        # If object is a byte stream and must be decoded
        if isinstance(message, bytes):
            message = message.decode("utf-8")

        # Create syslog-ng LogMessage
        msg = LogMessage(message)

        # Set PROGRAM field
        msg["PROGRAM"] = "Proofpoint-" + self.type

        # Only parse message as json if max_performance is False
        if self.max_performance is False:

            # Try to extract json fields for processing
            try:
                parsed = json.loads(message, strict=False)
            except json.JSONDecodeError as jde:
                self.logger.warning("Invalid json in %s : %s", message, jde)

            # Proofpoint sets event time in ts field
            if "ts" in parsed:
                stamp = parsed["ts"]
                try:
                    # Create datetime object from converted ts field and set it on LogMessage
                    datestamp = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%f%z")
                    utc = datestamp.astimezone(pytz.timezone('UTC'))
                    msg.set_timestamp(utc)
                except ValueError as ve:
                    self.logger.warning(ve)

        # Send message up the syslog-ng pipeline
        self.post_message(msg)
        self.counter = self.counter + 1


    def init(self, options): # optional
        """
        Initialize Proofpoint on Demand driver
        """

        # Initialize variables
        self.backfill_start = ""
        self.end_timestamp = ""
        self.counter = 0
        self.backfill_hours = 0
        self.exit = False

        # Set type of event to retrieve from configuration
        if "type" in options:
            if options["type"].lower() == "message":
                self.type = "message"
            elif options["type"].lower() == "maillog":
                self.type = "maillog"
            else:
                print("Invalid type (%s) requested" % options["type"])
        else:
            # Default to message
            self.type = "message"
            print("No log type specified, defaulting to message")

        # Initialize logger for driver
        self.logger = logging.getLogger('Proofpoint-' + self.type)
        stream_logger = logging.StreamHandler()

        # Standard log format
        log_format = " - ".join((
            "Proofpoint-%s" % self.type,
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

        # Log all options passed
        self.logger.debug("Driver options include: %s", options)

        # Set token
        if "token" in options:
            try:
                # Decode token and fail completely if unable to
                self.token = base64.b64decode(options["token"]).decode("utf-8")
            except Exception as ex:
                self.logger.error("Unable to decode token %s : %s", options["token"], ex)
                return False
        else:
            self.logger.error("No token specified in driver configuration")
            return False

        # Set Cluster ID
        if "cid" in options:
            self.cid = options["cid"]
        else:
            self.logger.error("No cid specified in driver configuration")
            return False

        # Set ssl_verify to false only if specified
        self.ssl_verify = True
        if "ssl_verify" in options:
            if options["ssl_verify"].lower() == "false":
                self.ssl_verify = False
                self.logger.info("Disabling SSL certificate verification for ssl_verify:%s", self.ssl_verify)

        # Set max_performance to True only if specified
        self.max_performance = False
        if "max_performance" in options:
            if options["max_performance"].lower() == "true":
                self.max_performance = True
                self.logger.info("Disabling performance impacting related message parsing")

        # Set backoff_time
        if "backoff_time" in options:
            try:
                self.backoff_time = int(options["backoff_time"])
            except Exception:
                self.logger.error("backoff_time must be an integer value : %s", options["backoff_time"])
                self.backoff_time = 10
        else:
            self.logger.info("No backoff_time specified in driver configuration, using 10 seconds")
            self.backoff_time = 10

        # Option to retrieve events from backfill_hours hours ago
        if "backfill_hours" in options:
            try:
                self.backfill_hours = int(options["backfill_hours"])
            except Exception:
                self.logger.error("backfill_hours must be an integer value for hours : %s", options["backfill_hours"])

        # Option to retrieve events starting from backfill_start
        if "backfill_start" in options:
            try:
                # Make sure this is a valid datetime format
                backfill_start = datetime.strptime(options["backfill_start"], "%Y-%m-%dT%H:%M:%S-0000")
                self.backfill_start = options["backfill_start"]

                # Get start time + backfill_hours hours for end of search window
                if self.backfill_hours > 0:
                    delta = timedelta(hours = self.backfill_hours)
                    end_time = backfill_start + delta

                    # Convert to Proofpoint allowed format
                    self.end_timestamp = end_time.strftime("%Y-%m-%dT%H:%M:%S") + "-0000"

                # If no end time is set with backfill_hours, the driver will receive a significant number
                # of duplicate events from Proofpoint when it switches back to realtime mode
                else:
                    self.logger.warning("backfill_start specified without backfill_hours, expect duplicate events from Proofpoint")

            # Do not startup if we have an invalid start date as this can unleash havoc
            except Exception as ex:
                self.logger.critical("Invalid backfill_start (%s) - should be in UTC YYYY-MM-DDTHH:MM:SS-0000", options["backfill_start"])
                self.logger.info("Shutting down driver due to invalid backfill_start configuration : %s", ex)
                self.request_exit()

        return True


    def run(self): # mandatory
        """
        Main loop to retrieve events from websock for Proofpoint on Demand
        """

        # Keep looping until we need to exit
        if not self.exit:
            self.logger.info("Pulling logs from Proofpoint on Demand API for %s", self.cid)

        while not self.exit:

            # Headers needed by Proofpoint
            headers={"Host":"logstream.proofpoint.com:443","Authorization":"Bearer %s" % self.token}

            # Turn on additional debugging if set
            if logging.DEBUG >= self.logger.getEffectiveLevel():
                self.logger.debug("Turning on trace logging for websocket")
                websocket.enableTrace(True)

            # If we already have a start and end timestamp
            if self.backfill_start and self.end_timestamp:
                self.logger.info("Start fetch window at %s", self.backfill_start)
                self.logger.info("End fetch window at %s", self.end_timestamp)
                wss_url = "wss://logstream.proofpoint.com:443/v1/stream?cid=%s&type=%s&sinceTime=%s&toTime=%s" \
                    % (self.cid, self.type, self.backfill_start, self.end_timestamp)

            # If we only have a starting timestamp
            elif self.backfill_start:
                self.logger.info("Start fetch window at %s", self.backfill_start)
                wss_url = "wss://logstream.proofpoint.com:443/v1/stream?cid=%s&type=%s&sinceTime=%s" % (self.cid, self.type, self.backfill_start)

            # Create a sinceTime if backfill_hours is set
            elif self.backfill_hours > 0:

                # Get current time - backfill_hours hours
                now = datetime.utcnow()
                delta = timedelta(hours = self.backfill_hours)
                start_time = now - delta

                # Convert to Proofpoint allowed format
                self.backfill_start = start_time.strftime("%Y-%m-%dT%H:%M:%S") + "-0000"
                self.logger.info("Start fetch window at %s", self.backfill_start)

                # Websocket URL for back in time
                wss_url = "wss://logstream.proofpoint.com:443/v1/stream?cid=%s&type=%s&sinceTime=%s" % (self.cid, self.type, self.backfill_start)
            else:
                # Websocket URL for current stream
                self.logger.info("Start fetch at current time")
                wss_url = "wss://logstream.proofpoint.com:443/v1/stream?cid=%s&type=%s" % (self.cid, self.type)

            # Create websocket with given parameters and handlers
            websocket.setdefaulttimeout(30)
            self.wsapp = websocket.WebSocketApp(
                wss_url,
                header=headers,
                on_error=self.on_error,
                on_close=self.on_close,
                on_message=self.on_message)

            # Run without SSL certificate verification if set
            if self.ssl_verify is False:
                self.wsapp.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE}, ping_interval=10, skip_utf8_validation=True)
            else:
                self.wsapp.run_forever(ping_interval=10, skip_utf8_validation=True)

            # Proofpoint will sometimes fail to return results but doesn't throw an error
            if self.counter == 0:
                self.logger.error("Websocket connection closed but no events were returned")
            else:
                self.logger.info("Websocket closed after %i events returned", self.counter)

            # Reset counter
            self.counter = 0

            # If a start and end were set for the fetch, exit after completion
            if self.backfill_start and self.end_timestamp and self.exit is False:
                self.logger.info("All events between %s and %s have been retreived", self.backfill_start, self.end_timestamp)
                self.request_exit()

            # If this was a backfill_hours search, make sure we start new searches at current time
            elif self.backfill_hours > 0 and self.exit is False:
                self.logger.info("Completed pulling logs starting from %s", self.backfill_start)
                self.backfill_hours = 0
                self.backfill_start = ""
                self.end_timestamp = ""

            # Should only be here if something breaks or we specified a sinceTime
            if self.exit is False:
                self.logger.info("Websocket connection lost, event duplication is likely")


    def request_exit(self): # mandatory
        """
        Cleanly shutdown websocket and exit driver
        """

        self.logger.info("Shutting down Proofpoint on Demand driver")
        self.exit = True
        try:
            self.wsapp.keep_running = False
            self.wsapp.close()
        except Exception as ex:
            self.logger.warning(ex)
        self.logger.info("Shutdown complete")
