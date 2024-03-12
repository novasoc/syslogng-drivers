"""
Copyright (c) 2024 Pillr

Use of this source code is governed by an MIT-style license that can be found in the LICENSE file or at https://opensource.org/licenses/MIT.

Original development by Dan Elder (delder@novacoast.com)
Syslog-ng Python parser for converting syslog-ng stats messages to key value pairs or alerts for upstream consumption

Additional documentation available at:
https://support.oneidentity.com/technical-documents/syslog-ng-premium-edition/7.0.33/administration-guide/90#TOPIC-2036755
"""

import logging
import re
import os
import configparser
import datetime
import smtplib
import ssl
import pickle
import os
import syslogng

class DedupAlerts(object):
    """
    syslog-ng parser for deduped alerting
    """

    def open(self):
        """
        Validate email connection parameters for sending alerts
        """

        # Test message
        test_message = """From: %s
To: %s
Subject: Syslog-ng Dedup Alert Engine Initializing

Please disregard this message
""" % (self.sender, self.test_recipient)

        # Send test email to validate SMTP settings
        if not self.email_alert(self.test_recipient, test_message):
            self.logger.error("Unable to send email")
            return False

        return True


    def close(self):
        """Close the connection to the target service"""
        pass


    def init(self, options):
        """
        This method is called at initialization time
        Should return false if initialization fails
        """

        # Initialize logger for driver
        self.logger = logging.getLogger('DedupAlerts')
        stream_logger = logging.StreamHandler()

        # Standard log format
        log_format = 'DedupAlerts - %(levelname)s - %(message)s'

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

        # Global watchlist and events
        self.watchlist = []
        self.events = {}

        self.processed = 0
        self.dropped = 0
        self.total = 0

        # Get/set all mail related options
        self.sender = "root@localhost"
        if "mail_sender" in options:
            self.sender = options["mail_sender"]
        
        self.password = False
        if "mail_password" in options:
            self.password = options["mail_password"]

        self.encryption = False
        if "mail_encryption" in options:
            self.encryption = options["mail_encryption"]

        self.smtp_server = "localhost"
        if "mail_server" in options:
            self.smtp_server = options["mail_server"]

        self.port = 25
        if "mail_port" in options:
            try:
                self.port = int(options["mail_port"])
            except Exception:
                self.logger.error("Invalid SMTP port specified : %s", options["mail_port"])

        self.trust_certificate = True
        if "mail_trust" in options:
            if options["mail_trust"].lower() == "false":
                self.trust_certificate = False

        self.test_recipient = "root@localhost"
        if "mail_test_recipient" in options:
            self.test_recipient = options["mail_test_recipient"]

        self.sender = "root@localhost"
        if "mail_sender" in options:
            self.sender = options["mail_sender"]

        # Check for state database options
        if "state_db" in options:
            self.state_db = options["state_db"]
            # Set stale_hours from options or default to 12
            if "stale_hours" in options:
                self.stale_hours = 12
                try:
                    self.stale_hours = int(options["stale_hours"])
                except Exception:
                    self.logger.error("Invalid value for stale_hours: %s", options["stale_hours"])                
            
            # Load previous state from last shutdown
            if not self.load_events():
                self.logger.error("Error accessing %s for tracking state between restarts", self.state_db)

        # Ensure alert configuration file is defined
        if not options["alerts_ini"]:
            self.logger.error("No alerts_ini configuration value set")
            return False

        # Read in alerts definitions
        alerts_ini = options["alerts_ini"]
        parser = configparser.ConfigParser()
        parser.read(alerts_ini)

        try:
            configurations = parser.sections()
            for configuration in configurations:

                alert = {}
                try:
                    # Get configuration values from ini
                    pattern = parser.get(configuration, "pattern")
                    recipient = parser.get(configuration, "recipient")
                    template = parser.get(configuration, "template")
                    keys = parser.get(configuration, "keys")
                    user = parser.get(configuration, 'user', fallback=False)
                    computer = parser.get(configuration, "computer", fallback=False)
                    log_sources = parser.get(configuration, "log_sources", fallback=False)
                    high_threshold = parser.getint(configuration, "high_threshold", fallback=1)
                    time_span = parser.getint(configuration, "time_span", fallback=60)
                    reset_time = parser.getint(configuration, "reset_time", fallback=60)
                    timestamp = parser.get(configuration, "timestamp", fallback=False)
                    timestamp_format = parser.get(configuration, "timestamp_format", fallback=False)
                    custom_field = parser.get(configuration, "custom_field", fallback=False)

                    # Convert the pattern regex to a logical AND search expression if whitespace is present
                    if re.search(" ", pattern):
                        # Split pattern by whitespace
                        logical_pattern = ""
                        for substring in pattern.split(" "):
                            # Use lookaheads for matching each substring
                            logical_pattern = logical_pattern + "(?=.*" + substring + ")"
                        # Match remainder of log
                        pattern = logical_pattern + ".*"
                        self.logger.debug("Converted search expression %s to %s", parser.get(configuration, "pattern"), pattern)

                    # Store configuration parameters for this alert
                    alert['name'] = configuration
                    alert['recipient'] = recipient
                    alert['pattern'] = pattern
                    alert['keys'] = keys
                    alert['template'] = template
                    alert['high_threshold'] = high_threshold
                    alert['time_span'] = time_span
                    alert['reset_time'] = reset_time
                    alert['timestamp'] = timestamp
                    alert['timestamp_format'] = timestamp_format

                    # Compile regex for performance
                    pattern_regex = re.compile(pattern)
                    alert['pattern_regex'] = pattern_regex
                    if user:
                        user_regex = re.compile(user)
                        alert['user_regex'] = user_regex
                    if computer:
                        computer_regex = re.compile(computer)
                        alert['computer_regex'] = computer_regex
                    if log_sources:
                        log_sources_regex = re.compile(log_sources)
                        alert['log_sources_regex'] = log_sources_regex
                    if timestamp:
                        timestamp_regex = re.compile(timestamp)
                        alert['timestamp_regex'] = timestamp_regex
                    if custom_field:
                        custom_field_regex = re.compile(custom_field)
                        alert['custom_field_regex'] = custom_field_regex

                    # Add this alert to the global watchlist
                    self.logger.debug("Adding %s (%s) to monitored alerts", configuration, pattern)
                    self.watchlist.append(alert)
                except Exception as ex:
                    self.logger.warning("Missing or invalid options for %s configuration : %s", configuration, ex)
                    return False

        except Exception as ex:
            self.logger.error("Error parsing %s : %s", alerts_ini, ex)
            return False

        return True

    def deinit(self):
        """
        Flush log file to disk
        """

        self.logger.debug("%i alarms generated (%i events did not generate alarms) out of %i logs", self.processed, self.dropped, self.total)

        # If configured to maintain state between restarts
        if self.state_db:
            timestamp_count = 0
            events_count = 0
            alarm_count = 0
            # Count events and timestamps in events
            for category in self.events:
                for event in self.events[category]:
                    events_count = events_count + 1
                    timestamp_count = timestamp_count + len(self.events[category][event]['timestamps'])
                    alarm_count = alarm_count + len(self.events[category][event]['alarms'])
            # Dump events to state file using pickle
            try:
                f = open(self.state_db, 'wb')
                pickle.dump(self.events, f)
                f.flush()
                f.close()
                self.logger.info("Flushed %i events with %i timestamps with %i alarms to %s",\
                                 events_count, timestamp_count, alarm_count, self.state_db)
            except Exception as ex:
                self.logger.error("Unable to flush events to %s : %s", self.state_db, ex)
        else:
            self.logger.info("No configuration for %s, event state discarded", self.state_db)


    def send(self,log_message):
        """
        Parse out syslog-ng stats messages to extract metrics and generate alerts if needed
        """
        self.total = self.total + 1
        # Set values from log_message
        syslog_timestamp = log_message['S_ISODATE']
        message = log_message['MESSAGE']

        # Convert bytes to strings if needed
        if isinstance(syslog_timestamp, bytes):
            syslog_timestamp = syslog_timestamp.decode("utf-8")
        if isinstance(message, bytes):
            message = message.decode("utf-8")

        # Check every alert in the watchlist against this log
        for alert in self.watchlist:

            if alert['pattern_regex'].search(message):

                # Create new metadata object
                metadata = {}

                # Extract and set user from event if available
                try:
                    metadata['user'] = alert['user_regex'].search(message).group(1)
                except:
                    metadata['user'] = "N/A"

                # Extract and set computer from event if available
                try:
                    metadata['computer'] = alert['computer_regex'].search(message).group(1)
                except:
                    metadata['computer'] = "N/A"

                # Extract and set log_sources from event if available
                try:
                    metadata['log_sources'] = alert['log_sources_regex'].search(message).group(1)
                except:
                    metadata['log_sources'] = "N/A"

                # Extract and set log_sources from event if available
                try:
                    metadata['custom_field'] = alert['custom_field_regex'].search(message).group(1)
                except:
                    metadata['custom_field'] = "N/A"

                # Set metadata for syslog-ng available macros
                metadata['LOGHOST'] = log_message['LOGHOST']
                metadata['SOURCEIP'] = log_message['SOURCEIP']
                metadata['FULLHOST'] = log_message['FULLHOST']
                metadata['FULLHOST_FROM'] = log_message['FULLHOST_FROM']

                # Cleanup metadata fields
                if isinstance(metadata['LOGHOST'], bytes):
                    metadata['LOGHOST'] = metadata['LOGHOST'].decode("utf-8")
                if isinstance(metadata['SOURCEIP'], bytes):
                    metadata['SOURCEIP'] = metadata['SOURCEIP'].decode("utf-8")
                if isinstance(metadata['LOGHOST'], bytes):
                    metadata['FULLHOST'] = metadata['FULLHOST'].decode("utf-8")
                if isinstance(metadata['FULLHOST_FROM'], bytes):
                    metadata['FULLHOST_FROM'] = metadata['FULLHOST_FROM'].decode("utf-8")


                # Extract timestamp from event if available and set
                if 'timestamp_regex' not in alert or 'timestamp_format' not in alert:
                    metadata['alert_date'] = datetime.datetime.strptime(syslog_timestamp, "%Y-%m-%dT%H:%M:%S%z")

                # Convert timestamp string to datetime if possible
                else:
                    try:
                        raw_timestamp = alert['timestamp_regex'].search(message).group(1)
                        metadata['alert_date'] = datetime.datetime.strptime(raw_timestamp, alert['timestamp_format'])
                    except Exception as ex:
                        self.logger.debug("Invalid timestamp format in %s : %s", message, ex)
                        metadata['alert_date'] = syslog_timestamp
                
                # Convert to unix timestamp from datetime
                timestamp = int(metadata['alert_date'].timestamp())
              
                # Build unique key for deduping alerts from keys fields
                key = ""
                for value in alert['keys'].split(','):
                    key = key + metadata[value] + "-"

                # If this type of event has never occured
                if alert['name'] not in self.events:
                    self.events[alert['name']] = {}

                # If this type of event for this key has occured
                if key in self.events[alert['name']]:
                    event = self.events[alert['name']][key]

                # If this type of event for this key has never occured
                else:
                    event = {}
                    event['timestamps'] = []
                    event['num_events'] = 0
                    event['alarms'] = []
                    self.events[alert['name']][key] = event

                # Add timestamp for this event
                self.events[alert['name']][key], alertable = self.insert_timestamp(alert, event, timestamp)

                # If we this is an alertable event
                if alertable:
                    message, temp_event = self.gen_alert(\
                            new_alert=alert,
                            new_event=self.events[alert['name']][key],
                            new_metadata=metadata,
                            new_timestamp=timestamp,
                            new_log=message)

                    # Send email alert
                    if self.email_alert(alert['recipient'], message):
                        # Overwrite event with modified (alarmed) event information
                        self.events[alert['name']][key] = temp_event
                        self.processed = self.processed + 1
                        return self.SUCCESS
                    else:
                        # Trigger re-opening connection
                        self.logger.error("Failed to send alert email")
                        return self.NOT_CONNECTED

                # Matching alert entry found, move on to next message
                self.dropped = self.dropped + 1
                return self.SUCCESS

        # No matching alert entry found
        self.dropped = self.dropped + 1
        return self.SUCCESS

    def insert_timestamp(self, new_alert, new_event, new_timestamp):
        """
        Inserts a new timestamp for a given alert into the series and determines if an alert condition exists
        """

        # Incriment num_event counter
        new_event['num_events'] = new_event['num_events'] + 1

        # Check if newest timestamp is within an existing alarm window
        for alarm in new_event['alarms']:
            if new_timestamp >= alarm - new_alert['time_span'] and new_timestamp <= alarm + new_alert['reset_time']:

                # This event falls within an existing alarm window
                return new_event, False

        # Events that should be alerted on for a single occurrence
        if new_alert['high_threshold'] == 1:
            #self.gen_alert(new_alert, new_event, metadata, new_timestamp, log)
            return new_event, True
        
        # Events that should be alerted on for multiple occurrences
        else:
            # Add timestamp to list
            new_event['timestamps'].append(new_timestamp)
            new_event['timestamps'].sort()
            timestamps = len(new_event['timestamps'])

            # If there aren't enough events to trigger an alarm
            if timestamps < new_alert['high_threshold']:
                return new_event, False

            # Find this timestamp index in the list of timestamps
            position = new_event['timestamps'].index(new_timestamp)

            # Count duplicates in list not including the timestamp itself
            duplicates = new_event['timestamps'].count(new_timestamp) - 1

            # If there are at least high_threshold events after this timestamp
            if position + new_alert['high_threshold'] + duplicates <= timestamps:

                # Max timestamp value to evaluate for first entry in list
                max_timestamp = position + duplicates

            else:
                # Max timestamp  for first entry is at end of list
                max_timestamp = timestamps - new_alert['high_threshold']

            # If there are more than high_threshold events before this one
            if position - new_alert['high_threshold'] >= 0:

                # Start comparing timestamps high_threshold events before this one
                min_timestamp = position - new_alert['high_threshold']

            else:
                # Start comparing timestamps high_threshold events into the list
                min_timestamp = 0

            # Compare the delta between min_timestamp and min_timestamp + high_threshold up to max_timestamp
            while min_timestamp <= max_timestamp:
                # If the high timestamp - low timestamp is <= time_span
                low = new_event['timestamps'][min_timestamp]
                high = new_event['timestamps'][min_timestamp + new_alert['high_threshold'] - 1]
                if high - low <= new_alert['time_span']:
                    #gen_alert(new_alert, new_event, metadata, new_timestamp, log)
                    return new_event, True
                
                # Incriment min_timestamp position
                min_timestamp = min_timestamp + 1

        # No alert to generate
        return new_event, False

    def gen_alert(self, new_alert, new_event, new_metadata, new_timestamp, new_log):
        """
        Generate an alert with the required template variable subsitution
        """

        message = new_alert['template']

        # Replace template variables
        message = message.replace('$RECIPIENT', new_alert['recipient'])
        message = message.replace('$PATTERN', new_alert['pattern'])
        message = message.replace('$LOG_SOURCES', new_metadata['log_sources'])
        message = message.replace('$USER', new_metadata['user'])
        message = message.replace('$COMPUTER', new_metadata['computer'])
        message = message.replace('$CUSTOM_FIELD', new_metadata['custom_field'])
        message = message.replace('$ALERT_TIME', str(new_metadata['alert_date']))
        message = message.replace('$HIGH_THRESHOLD', str(new_alert['high_threshold']))
        message = message.replace('$TIME_SPAN', str(new_alert['time_span']))
        message = message.replace('$RESET_TIME', str(new_alert['reset_time']))
        message = message.replace('$NUM_EVENTS', str(new_event['num_events']))
        message = message.replace('$LOGHOST', str(new_metadata['LOGHOST']))
        message = message.replace('$SOURCEIP', str(new_metadata['SOURCEIP']))
        message = message.replace('$FULLHOST', str(new_metadata['FULLHOST']))
        message = message.replace('$FULLHOST_FROM', str(new_metadata['FULLHOST_FROM']))
        message = message.replace('$LOG', new_log)

        # Reset event counter
        new_event['num_events'] = 0

        # Add this alarm to all alarms for event
        new_event['alarms'].append(new_timestamp)

        # Clean list of timestamps to copy to
        new_timestamps = []
        initial_timestamps = len(new_event['timestamps'])

        # For all event timestamps within time_span of new_timestamp plus reset_time
        counter = 0
        min_stamp = new_timestamp - new_alert['time_span']
        max_stamp = new_timestamp + new_alert['reset_time']
        while counter < len(new_event['timestamps']):
            # If this timestamp falls within outside the alarm window
            if new_event['timestamps'][counter] > max_stamp or new_event['timestamps'][counter] < min_stamp:
                # Add it to list of clean timestamps
                new_timestamps.append(new_event['timestamps'][counter])
            
            # Increment counter to check next value
            counter = counter + 1

        # Replace timestamps with trimmed list of timestamps
        new_event['timestamps'] = new_timestamps
        self.logger.debug("Trimmed %i timestamps after alert generation", initial_timestamps - len(new_timestamps))

        # Return message and cleaned up event
        return message, new_event


    def email_alert(self, recipient, message):
        """
        Send a given message to the recipent
        """

        self.logger.debug(f"Sending {len(message)} character email: {message}")

        # If no encryption should be used
        if not self.encryption:
            try:
                server = smtplib.SMTP(self.smtp_server, self.port)

                # If a username and password have been supplied
                if self.password and len(self.sender) > 0:
                    # Authenticate in cleartext
                    server.login(self.sender, self.password)
                server.sendmail(from_addr=self.sender, to_addrs=recipient, msg=message)
                server.quit()
                return True
            except Exception as e:
                self.logger.error("Failed to send cleartext message : %s", e)
                return False

        # Disable certificate verification if needed
        if self.trust_certificate:
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context()

        # Handle SSL encrypted SMTP
        if self.encryption.lower() == "ssl":

            # Try to setup a secure connection using SSL
            try:
                server = smtplib.SMTP_SSL(self.smtp_server, self.port, context=context)
                server.login(self.sender, self.password)
                server.sendmail(from_addr=self.sender, to_addrs=recipient, msg=message)
                server.quit()
                return True
            except Exception as e:
                self.logger.error("SMTP over SSL issue : %s", e)
                # Secure connection failure, do not send email
                return False

        # Handle STARTTLS encrypted SMTP
        elif self.encryption.lower() == "starttls":
                
            # Try to setup a secure connection using STARTTLS
            try:
                server = smtplib.SMTP(self.smtp_server, self.port, context)
                server.starttls(context=context)
                server.login(self.sender, self.password)
                server.sendmail(from_addr=self.sender, to_addrs=recipient, msg=message)
                server.quit()
                return True
            except Exception as ex:
                self.logger.error("SMTP over starttls issue : %s", ex)
                # Secure connection failure, do not send email
                return False

        # Invalid encrypt setting
        else:
            self.logger.error("Invalid setting for encryption : %s", self.encryption)
            return False


    def load_events(self):
        """
        Load events from disk and purge older timestamps
        """

        try:
            # If state_db exists
            if os.path.exists(self.state_db):
                # If state_db isn't readable
                if not os.access(self.state_db, os.R_OK):
                    self.logger.error("%s exists but is unreadable", self.state_db)
                    return False
                # If state file exists but isn't writable
                if not os.access(self.state_db, os.W_OK):
                    self.logger.error("%s exists but is not writable", self.state_db)
                    return False
            else:
                # Create empty state file if it doesn't exist
                fp = open(self.state_db, "bw")
                fp.flush()
                fp.close()
                return True
        except Exception as ex:
            self.logger.error("Error accessing state_db (%s) : %s", self.state_db, ex)
            return False

        # Read events from file and load them with pickle
        try:
            f = open(self.state_db, 'rb')
            self.events = pickle.load(f)
            f.flush()
            f.close()
        except Exception as ex:
            self.logger.error("Unable to load events from %s : %s", self.state_db, ex)
            return False

        # Internal counters
        event_counter = 0
        timestamp_counter = 0
        purged_events = 0
        alarm_count = 0

        # Calculate time delta for maximum age of events to track
        current_time = datetime.datetime.utcnow()
        past_time = datetime.timedelta(hours=self.stale_hours)
        limit = int((current_time - past_time).timestamp())

        # Loop through every event from state_db and check timestamps against limit
        for category in self.events:
            for event in self.events[category]:
                event_counter = event_counter + 1
                alarm_count = alarm_count + len(self.events[category][event]['alarms'])
                new_timestamps = []
                for timestamp in self.events[category][event]['timestamps']:
                    # Compare each timestamp against limit
                    if timestamp >= limit:
                        new_timestamps.append(timestamp)
                        timestamp_counter = timestamp_counter + 1
                    else:
                        purged_events = purged_events + 1
                # Replace timestamps rather with new list rather than potentially performing multiple pop() operations
                self.events[category][event]['timestamps'] = new_timestamps

        self.logger.info("Imported %i events with %i timestamps (%i timestamps discarded due to age) with %i alarms",\
                         event_counter, timestamp_counter, purged_events, alarm_count)
        return True

class StatsParser(object):
    """
    syslog-ng parser for handling internal statistics messages
    """

    def init(self, options):
        """
        This method is called at initialization time
        Should return false if initialization fails
        """

        # Initialize logger for driver
        self.logger = logging.getLogger('StatsParser')
        stream_logger = logging.StreamHandler()

        # Standard log format
        log_format = " - ".join((
            "StatsParser",
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

        self.logger.debug("Starting syslog-ng stats parser")

        # Ensure event_regex parameter is defined
        event_regex = r"\s(processed|dropped|queued|memory_usage)='([\w\.]+?)\(([\w\-\.]+)#?(.*?)\)=(\d+)'"
        if "event_regex" in options:
            event_regex = options["event_regex"]
        self.logger.debug("Event regex set to %s", event_regex)

        # Ensure ip_regex parameter is defined
        ip_regex = r"s_(\w+)[-_]+(\d+)[_-](\d+)-(\w+)"
        if "ip_regex" in options:
            ip_regex = options["ip_regex"]
        self.logger.debug("IP regex set to %s", ip_regex)

        # Ensure filters parameter is defined
        self.filters = "di_config_change,di_internal_alert,di_messages,di_class_violation,di_ssb,di_local,ds_local,ds_center,dst.file,dst.program,dst.logstore,dst.file,center,src.program,src.facility,src.host,src.internal,src.journald,src.severity,src.sender,si.local,si_local,si.internal,internal_source,internal_queue_length,localhost,msg_clones,payload_reallocs,scratch_buffers_count,scratch_buffers_bytes,sdata_updates,tag,license_host_usage,license_monthly_consumed_hosts".split(',')
        if "filters" in options:
            self.filters = options["filters"].split(',')
        self.logger.debug("Statistic filters set to : %s", self.filters)

        # Check if alerting should be enabled
        self.alert_log = False
        if "alert_log" in options:
            try:
                self.alert_log = open(options["alert_log"], "+a")
                self.syslog_hosts = {}
                self.logger.info("Alerts will be logged to %s", options["alert_log"])
            except Exception as ex:
                self.logger.error("Unable to write alerts to %s : %s", options["alert_log"], ex)

        # Check if alert_filter parameter is defined
        self.alert_filter = "license_host_usage,license_monthly_consumed,memory_usage".split(',')
        if "alert_filter" in options:
            self.alert_filter = options["alert_filter"].split(',')
        self.logger.debug("Alert filters set to : %s", self.alert_filter)

        # Compile regex for performance
        try:
            self.event_regex = re.compile(event_regex)
            self.ip_regex = re.compile(ip_regex)
        except Exception as ex:
            self.logger.error("Unable to compile regular expression : %s", ex)

        return True

    def deinit(self):
        """
        Flush log file to disk
        """

        if self.alert_log:
            try:
                self.alert_log.close()
            except Exception as ex:
                self.logger.error("Unable to flush alert_log : %s", ex)
                return False
        return True

    def parse(self,log_message):
        """
        Parse out syslog-ng stats messages to extract metrics and generate alerts if needed
        """

        # Set values from log_message
        timestamp = log_message['S_ISODATE']
        message = log_message['MESSAGE']
        host = log_message['HOST']

        # Convert bytes to strings if needed
        if isinstance(timestamp, bytes):
            timestamp = timestamp.decode("utf-8")
        if isinstance(message, bytes):
            message = message.decode("utf-8")
        if isinstance(host, bytes):
            host = host.decode("utf-8")

        # Extract all metrics from a syslog-ng stats message
        metrics = self.event_regex.findall(message)

        if not metrics:
            self.logger.debug("No valid metrics found in %s", message)
            self.logger.debug("Using a filter before this parser such as:\nfilter f_stats { message('^Log statistics'); }; \nis recommended")
            return False

        # Initialize list of keys
        keys = {}

        # Loop through all metrics
        for metric in metrics:

            # Standardize name of metric
            key = f"{metric[2]}-{metric[0]}"

            # Cleanup duplicate d_ or s_
            key = key.replace(".d_d_", ".d_")
            key = key.replace(".s_s_", ".s_")

            # Remove IP octet from source if present
            match = self.ip_regex.search(key)
            if match:
                key = f"{match.group(1)}-{match.group(2)}-{match.group(4)}"

            # Filter out metrics we don't care about
            if self.filters:
                if metric[1] not in self.filters and metric[2] not in self.filters:
                    if key not in keys:
                        keys[key] = metric[4]

            # If there are no filters defined include everything
            else:
                if key not in keys:
                    keys[key] = metric[4]

        # Rewrite message to key=value format
        new_message = ""
        for key, value in keys.items():
            new_message = new_message + f' {key}={value}'
        log_message['MESSAGE'] = new_message

        # Check against previous metrics if alerting is enabled
        if self.alert_log:

            # Start with empty alert value
            alerts = ""

            # Check if we've seen this host before
            if host in self.syslog_hosts:

                # Check if we've seen this key before
                for key, value in self.syslog_hosts[host].items():

                    # Check against previous value
                    if key in keys and key not in self.alert_filter:

                        # Convert to int for comparison purposes
                        oldvalue = int(value)
                        newvalue = int(keys[key])

                        # For dropped we want the number to be unchanged
                        if "dropped" in key:
                            if newvalue > oldvalue:
                                try:
                                    self.alert_log.write(f'WARN {timestamp} - {key} is increasing on {host} ({oldvalue}=>{newvalue})\n')
                                except Exception as ex:
                                    self.logger.critical("Unable to write to alert log : %s", ex)
                                alerts = alerts + f'ALERT - {key} is increasing on {host} ({oldvalue}=>{newvalue}) '

                        # For queued we want the number to be lower
                        elif "queued" in key:
                            if newvalue > oldvalue:
                                try:
                                    self.alert_log.write(f'INFO {timestamp} - {key} is increasing on {host} ({oldvalue}=>{newvalue})\n')
                                except Exception as ex:
                                    self.logger.critical("Unable to write to alert log : %s", ex)
                                alerts = alerts + f'WARN - {key} is increasing on {host} ({oldvalue}=>{newvalue}) '

                        # For processed we want the number to be higher
                        elif "processed" in key:
                            if newvalue == oldvalue:
                                try:
                                    self.alert_log.write(f'WARN {timestamp} - {key} is unchanged on {host} ({oldvalue}=>{newvalue})\n')
                                except Exception as ex:
                                    self.logger.critical("Unable to write to alert log : %s", ex)
                                alerts = alerts + f'ALERT - {key} is unchanged on {host} ({oldvalue}=>{newvalue}) '

            # Keep track or results for this host for next pass
            self.syslog_hosts[host] = keys

            # Set new ALERTS macro for message
            log_message['ALERTS'] = alerts

            # Flush alerts to disk
            self.alert_log.flush()
            os.fsync(self.alert_log.fileno())

        return True
