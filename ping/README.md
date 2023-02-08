# syslogng-pingone

## Purpose

This is a python syslogng.LogFetcher implementation designed to fetch events from PingOne via their [Admin REST API](https://admin-api.pingone.com/v3-beta/api-docs/).


## Installation

To install and configure the PingOne driver, create a new SCL directory for the driver and copy pingone.py and plugin.conf to it:

    /opt/syslog-ng/share/syslog-ng/include/scl/pingone/


## Components

### pingone.py

This is the syslogng.LogFetcher implementation which can be configured as a standalone source in syslog-ng. 

To configure the source, certain parameters are required:

    source s_pingone {
        python-fetcher(
            class("pingone.PingAdmin")
            options(
                "client_id","<Ping supplied Client ID>"
                "client_secret" "<Ping supplied Client Secret>"
                "accountId" "<Ping supplied Account ID>"
                "id" "<Ping supplied ID>"
                "disk_buffer" "<Location to store in-memory events during >" # optional
                "log_level" "<DEBUG|INFO|WARN|ERROR>" # optional - defaults to INFO
            )
            flags(no-parse)
            fetch-no-data-delay(<seconds to wait before attempting a fetch after no results are returned>)
        );
    };

Here are sample values as a reference:

    source s_pingone {
        python-fetcher(
            class("pingone.PingAdmin")
            options(
                "client_id","xxxxxxx"
                "client_secret" "xxxxxxx"
                "accountId" "xxxxxxx"
                "id" "xxxxxxx"
                "disk_buffer" "/var/run/ping.buffer" # optional
                "log_level" "DEBUG" # optional - defaults to INFO
            )
            flags(no-parse)
            fetch-no-data-delay(60)
        );
    };