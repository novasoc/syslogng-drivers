# pillr

## Purpose

This is a general collection of syslog-ng enhancements

## Dependencies

This driver requires the Python dateutil module to be available which is not included with syslog-ng PE. There are several ways to access it including:

Install the required module directly into the syslog-ng PE installation

    /opt/syslog-ng/bin/python3 -m pip install python-dateutil

Use the base OS Python modules for syslog-ng by modifying plugin.conf for the correct local path:

    sys.path.append("/usr/lib/python3.8/site-packages/")

To fully validate SSL certificates it may also be necessary to install the certifi module and upgrade the cacerts

    /opt/syslog-ng/bin/python3 -m pip install --upgrade certifi


## Installation

To install and configure the pillr Python extension, create a new SCL directory for the driver and copy pillr.py and plugin.conf to it:

    /opt/syslog-ng/share/syslog-ng/include/scl/pillr/

## Components

### pillr.py

#### Installation

The Pillr driver can be used by:

1. Create a new SCL directory named pillr (/opt/syslog-ng/share/syslog-ng/include/scl/pillr/)
2. Save plugin.conf to /opt/syslog-ng/share/syslog-ng/include/scl/pillr/plugin.conf
3. Save pillr.py to /opt/syslog-ng/share/syslog-ng/include/scl/pillr/pillr.py

#### StatsParser

The StatsParser functionality is designed to parse standard syslog-ng stats messages into key=value pairs and optionally generate a log of alerts from them. It can:
* Filter out metrics that aren't needed
* Rewrite metric names to be cleaner and more human readable
* Convert statistics messages into key=value pairs for easier upstream processing
* Create alerts for specific conditions (number of processed logs hasn't changed, number of dropped logs is increasing, number of queued logs is increasing)
* Filter out alerts for specific metrics

The parser itself does not require any parameters to be set and can:

    parser p_stats_parser {
        python(
            class("pillr.StatsParser")
        );
    };

The full options include:

    parser p_stats_parser {
        python(
            class("pillr.StatsParser")
            options(
                "log_level","debug"
                "filters","" # A comma separated list of metrics to filter out of reporting
                "alert_log","" # A file path to where alerts should be logged 
                "alert_filter","" # Metrics that shouldn't be alerted on
                "event_regex","" # A custom regex for parsing events to extract metrics
                "ip_regex","" # A custom regex for catching IP addresses in metrics to filter them out
            )
        );
    };

A sample configuration for reference:

    parser p_stats_parser {
        python(
            class("pillr.StatsParser")
            options(
                "log_level","debug"
                "filters","di_config_change,di_internal_alert,di_messages,di_class_violation,di_ssb,di_local,ds_local,ds_center,dst.file,dst.program,dst.logstore,dst.file,center,src.program,src.facility,src.host,src.internal,src.journald,src.severity,src.sender,si.local,si_local,si.internal,internal_source,internal_queue_length,localhost,msg_clones,payload_reallocs,scratch_buffers_count,scratch_buffers_bytes,sdata_updates,tag,license_host_usage,license_monthly_consumed_hosts"
                "alert_log","/tmp/alerts.log"
                "alert_filter","license_host_usage,license_monthly_consumed,memory_usage"
                "event_regex","\\s(processed|dropped|queued|memory_usage)='([\\w\\.]+?)\\(([\\w\\-\\.]+)#?(.*?)\\)=(\\d+)'"
                "ip_regex","s_(\\w+)[-_]+(\\d+)[_-](\\d+)-(\\w+)"
            )
        );
    };

#### StatsParser options

log_level - What level of logging to output (DEBUG, INFO, WARN, ERROR) from syslog-ng

filters - Comma separated list of metrics to ignore, default is di_config_change,di_internal_alert,di_messages,di_class_violation,di_ssb,di_local,ds_local,ds_center,dst.file,dst.program,dst.logstore,dst.file,center,src.program,src.facility,src.host,src.internal,src.journald,src.severity,src.sender,si.local,si_local,si.internal,internal_source,internal_queue_length,localhost,msg_clones,payload_reallocs,scratch_buffers_count,scratch_buffers_bytes,sdata_updates,tag,license_host_usage,license_monthly_consumed_hosts

alert_log - The path to a file that should be appended to with alerts based off metric values increasing (dropped events or queued events) or not increasing (processed event counters). This log file can be consumed by other systems or a syslog-ng file() driver and used to generate alerts for potential issues in the environment (messages queuing up or being dropped and when new log messages aren't coming in)

alert_filter - Comma separated list of metrics not to alert on, default is license_host_usage,license_monthly_consumed,memory_usage

event_regex - The custom regex (if needed) for capturing metrics from a statistics message (must escape backslash characters), default is \\s(processed|dropped|queued|memory_usage)='([\\w\\.]+?)\\(([\\w\\-\\.]+)#?(.*?)\\)=(\\d+)

ip_regex - The custom regex (if needed) for stripping out IP octets from metric names to clean them up (must escape backslash characters), default is s_(\\w+)[-_]+(\\d+)[_-](\\d+)-(\\w+)


#### DedupAlerts

DedupAlerts is a Python syslog-ng destination driver designed aggregate events for a given time period into a single event and generate an email alert. Duplicate event characteristics and alerting thresholds are defined in an .ini file to allow for flexible duplicate detection and noise mitigation.

The destination driver has one required parameters as well as optional ones. At a minimum, the following configuration is required:

    destination d_dedup_alerts {
        python(
            class("pillr.DedupAlerts")
            options(
                "alerts_ini","" # Path to ini configuration file defining duplicate event settings
            )
        );
    };

The full options include:

    destination d_dedup_alerts {
        python(
            class("pillr.DedupAlerts")
            options(
                "log_level","(debug|info|warn|error|crit)" # log level for output (defaults to info)
                "alerts_ini","" # Path to ini configuration file defining duplicate event settings
                "state_db","" # Path to file to create/use for maintaining event state database between restarts (defaults to not maintaining state)
                "stale_hours","" # How many hours old should imported events from state databse be before they're purged (defaults to 12)
                "mail_sender","" # Email address to use for sending mail (defaults to root@localhost)
                "mail_password","" # Password to use for acount sending email (defaults to no password and no authentication)
                "mail_server","" # FQDN or IP address of server to send mail through (defaults to localhost)
                "mail_encryption","(ssl|starttls|false)" # What encryption method to use (defaults to no encryption - False)
                "mail_port","" # Port used for SMTP connection (defaults to 25)
                "mail_trust","(true|false)" # Whether to require a trusted certificate for encrypted SMTP connections (defaults to True)
                "mail_test_recipient","" # On driver initialization, a test email will be sent to this user to validate SMTP settings (defaults to root@localhost)
            )
        );
    };

A sample configuration for reference:

    destination d_dedup_alerts {
        python(
            class("pillr.DedupAlerts")
            options(
                "log_level","warn" # log level for output (defaults to info)
                "alerts_ini","/opt/syslog-ng/etc/dedup.ini" # Path to ini configuration file defining duplicate event settings
                "state_db","/opt/syslog-ng/var/dedup.db" # Path to file to create/use for maintaining event state database between restarts (defaults to not maintaining state)
                "stale_hours","6" # How many hours old should imported events from state databse be before they're purged (defaults to 12)
                "mail_sender","me@mydomain.com" # Email address to use for sending mail (defaults to root@localhost)
                "mail_password","secret" # Password to use for acount sending email (defaults to no password and no authentication)
                "mail_server","mail.mydomain.com" # FQDN or IP address of server to send mail through (defaults to localhost)
                "mail_encryption","ssl" # What encryption method to use (defaults to no encryption - False)
                "mail_port","465" # Port used for SMTP connection (defaults to 25)
                "mail_trust","true" # Whether to require a trusted certificate for encrypted SMTP connections (defaults to True)
                "mail_test_recipient","you@mydomain.com" # On driver initialization, a test email will be sent to this user to validate SMTP settings (defaults to root@localhost)
            )
        );
    };

#### DedupAlerts options

log_level - What level of logging to output (DEBUG, INFO, WARN, ERROR) from syslog-ng
alerts_ini - Filesystem path to the configuration file defining what events to look for and all other settings for that alert
state_db - Filesystem path to a file (which will be created if necessary) for maintaining the list of events that have been tracked by the driver for using during syslog-ng restart/reload operations (by default state will not be maintained)
stale_hours - How many hours back should events from the state_db be imported on driver startup
mail_sender - Email address to be used when sending email alerts
mail_password - Password for mail_sender account
mail_server - FQDN or IP address of mail server to send email through
mail_encryption - Currently supported options are ssl, starttls, or none (default is none) for connection to mail_server
mail_port - Port to use for communication to mail_server (default is 25)
mail_trust - Whether communication to mail_server requires this system to validate and trust the certificate presented (when mail_encryption is not none)
mail_test_recipient - To validate email configuration, a test message will be sent to this address on driver startup

#### alerts_ini options

The file specified for the alerts_ini configuration includes a number of options and can have multiple stanzas. These include:

name - Each configuration must have a unique name (mandatory)
pattern - The regex to be used against a log message to check if it matches this configuration. Whitespace is interpreted as a logical AND for the regex (mandatory)
recipient - The email recipient(s) when an alert is triggered. Multiple email addresses must be separated by a comma (mandatory)
keys - A comma separated list of extracted variable(s) that are used to uniquely identify an event for dedup purposes
template - The email template to be used when an alert is triggered including variable substitutions (mandatory)
high_threshold - The number of events at which an alert should be triggered (default is 1)
time_span - The amount of time over which high_threshold events can occur before an alert is triggered in seconds (default is 60)
reset_time - The amount of time before or after the start or end of an alert before a new alert can be sent
timestamp - The regex to be used for extracting a timestamp from the message (optional)
timestamp_format - The timestamp format expression used for conversting the timestamp match to a datetime (if not defined, driver will attempt to autodetect) 
user - The regex to use for extracting a username from an event (optional)
computer - The regex to use for extracting a computer name from an event (optional)
log_sources - The regex to user for extracting the log sources from an event (optional)
custom_field - The regex to user for extracting a custom field from an event (optional)
template - the email template to use when sending messages including the variables to be replaced. If there is a Subject: line in the template, the message subject will be set to the contents of the Subject: line in the template

Referece configuration stanzas (of which there can be multiple in the alerts_ini file):

    [WindowsLockout]
    Pattern=4740 Microsoft-Windows-Security-Auditing
    Recipient=secops@company.com
    Timestamp=MSWinEventLog\s+\d+\s+\w+\s+\d+\s+(\w+\s+\w+\s+\d\d\s+\d\d:\d\d:\d\d\s+\d\d\d\d)
    Timestamp_Format=%%a %%b %%d %%H:%%M:%%S %%Y
    User=Account\s+That\s+Was\s+Locked\s+Out:\s+.*?Account\s+Name:\s+(.+?)\s+Additional
    Computer=Caller\s+Computer\s+Name:\s+[\\]*(.+?)\s+
    Log_Sources=Success\s+Audit\s+(.+?)\s+
    Keys=user,computer,log_sources
    High_Threshold=1
    Time_Span=60
    Reset_Time=60
    Template=Subject: Account Lockout Alert from $SOURCEIP
        Name: Search-Filter AcctLockout
        Alert=Windows Lockout
        Log Source/Domain Controller=$LOG_SOURCES
        Message=$LOG
        Appliance Detecting Alert=SSB
        Detection Time=$ALERT_TIME
        User=$USER
        Computer=$COMPUTER
        High threshold: $HIGH_THRESHOLD matches within $TIME_SPAN seconds.
        Subsequent alerts will not be sent until $RESET_TIME seconds have passed. There were $NUM_EVENTS alertable events since last alert message.
        Alert Recipients=$RECIPIENT


    [InterfaceDown]
    Pattern=interface\s+\w+\s+down
    Recipient=netops@company.com
    custom_field=interface\s+(\w+)\s+down
    Keys=SOURCEIP,custom_field
    High_Threshold=1
    Time_Span=60
    Reset_Time=60
    Template=Subject: Interface $CUSTOM_FIELD down on $SOURCEIP
        Detected pattern $PATTERN
        Log=$LOG


    [Cisco_IOS_EIGRP_Peer_Graceful_Restart]
    Pattern=EIGRP.+?Peer\s+graceful-restart
    Recipient=netops@company.com,secops@company.com
    Timestamp=:\s+(\w\w\w\s+\d+\s+\d+:\d+:\d+\.\d+\s+.+?):
    Keys=SOURCEIP
    High_Threshold=1
    Time_Span=60
    Reset_Time=3600
    Template=Subject: Detected Alert: Cisco IOS EIGRP Peer Graceful-restart for Device $SOURCEIP
        Alert=Cisco IOS EIGRP Peer Graceful-restart
        Device=$SOURCEIP
        Message=$LOG
        Appliance Detecting Alert=$LOGHOST
        Detection Time=$ALERT_TIME
        Container/Group Being Monitored=CiscoIOS
        High threshold: $HIGH_THRESHOLD matches within $TIME_SPAN seconds. 
        Subsequent alerts will not be sent until $RESET_TIME seconds have passed. 
        There were $NUM_EVENTS alertable events since the last alert message. 
        Alert Recipients=$RECIPIENT


In the email template configuration, the following substitutions are available which will replace the variable before sending the message:

    $LOGHOST - The hostname of the computer running syslog-ng PE — it returns the same result as the hostname command.
    $SOURCEIP - IP address of the host that sent the message to syslog-ng. (That is, the IP address of the host in the ${FULLHOST_FROM} macro.) Please note that when a message traverses several relays, this macro contains the IP of the last relay.
    $FULLHOST - The name of the source host where the message originates from.
    $FULLHOST_FROM - The FQDN of the host that sent the message to syslog-ng as resolved by syslog-ng using DNS. If the message traverses several hosts, this is the last host in the chain.
    $RECIPIENT - Value of recipient in alerts_ini configuration for this alert
    $PATTERN - Value of pattern in alerts_ini configuration for this alert
    $LOG_SOURCES - Value of regex contents matching log_sources in alerts_ini configuration for this alert
    $USER - Value of regex contents matching user in alerts_ini configuration for this alert
    $COMPUTER - Value of regex contents matching computer in alerts_ini configuration for this alert
    $CUSTOM_FIELD - Value of regex contents matching custom_field in alerts_ini configuration for this alert
    $ALERT_TIME - Either the timestamp within the message (as extracted and parsed from timestamp and timestamp_format in alerts_init) or time the event was received
    $HIGH_THRESHOLD - Value of high_threshold in alerts_ini configuration for this alert
    $TIME_SPAN - Value of time_span in alerts_ini configuration for this alert
    $RESET_TIME - Value of reset_time in alerts_ini configuration for this alert
    $NUM_EVENTS - Number of matching events within alert window
    $LOG - The MESSAGE field of the log message
