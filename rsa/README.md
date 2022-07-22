# syslogng-rsa

## Purpose

This is a python syslogng.LogFetcher implementation designed to fetch events from RSA SecurID Cloud via their [REST API for User Events](https://community.securid.com/t5/securid-cloud-authentication/cloud-administration-user-event-log-api/ta-p/623082) and their [REST API for Admin Events](https://community.securid.com/t5/securid-cloud-authentication/cloud-administration-event-log-api/ta-p/623069) for ingestion by syslog-ng.



## Installation

To install and configure the RSA SecurID Cloud driver, create a new SCL directory for the driver and copy rsa.py and plugin.conf to it:

    /opt/syslog-ng/share/syslog-ng/include/scl/rsa/

This driver requires additional Python modules not included in the syslog-ng PE distribution. The jwt and PyJWT module and its dependencies can be installed directly into your syslog-ng PE deployment by doing:

    /opt/syslog-ng/bin/python3 -m pip install jwt
    /opt/syslog-ng/bin/python3 -m pip install PyJWT

They can albe be installed to the underlying Linux distribution for Python 3.8 and referenced in the plugin.conf with:

    sys.path.append("/usr/lib/python3.8/site-packages/")
    sys.path.append("/usr/lib64/python3.8/site-packages/")

These paths can be adjusted as needed for your Linux distribution.

## Components

### rsa.py

This is the syslogng.LogFetcher implementation which can be configured as a standalone source in syslog-ng. 

To configure the source, certain parameters are required:

    source s_rsa_admin {
        python-fetcher(
            class("rsa.SecurIDCloud")
            options(
                "url","<url to RSA SecurID Cloud"
                "rsa_key" "<path to RSA key"
            )
            flags(no-parse)
            persist-name(s_rsa_admin)
        );
    };

Additional options can also be specified:

    source s_rsa_admin {
        python-fetcher(
            class("rsa.SecurIDCloud")
            options(
                "log_type","<admin|user>"
                "url","<url to RSA SecurID Cloud>"
                "rsa_key" "<path to RSA key>"
                "log_level","<DEBUG|INFO|WARN|ERROR>"
                "page_size","<number of results to return in a single page>"
                "max_performance","<True|False>"
                "initial_hours","<number of hours to search backward on initial fetch>"
                "ignore_persistence","<True|False>"
                "ssl_verify","<True|False>"
            )
            flags(no-parse)
            persist-name(s_rsa_admin)
            fetch-no-data-delay(<seconds to wait before attempting a fetch after no results are returned>)
        );
    };

Here are sample values as a reference:

    source s_rsa_admin {
        python-fetcher(
            class("rsa.SecurIDCloud")
            options(
                "log_type","admin"
                "url","https://na3.access.securid.com"
                "rsa_key" "/opt/syslog-ng/etc/securid.key"
                "log_level","INFO"
                "page_size","1000"
                "max_performance","False"
                "initial_hours","24"
                "ignore_persistence","False"
                "ssl_verify","True"
            )
            flags(no-parse)
            persist-name(s_rsa_admin)
            fetch-no-data-delay(<seconds to wait before attempting a fetch after no results are returned>)
        );
    };


### Driver options

log_type - Whether to retrieve admin events or user events

url - URL for RSA SecurID Cloud API access ('https://na3.access.securid.com')

rsa_key - path to [RSA SecurID Cloud API key](https://community.securid.com/t5/securid-cloud-authentication/manage-the-cloud-administration-api-keys/ta-p/623066)

log_level - the logging level (DEBUG, INFO, WARN, ERROR, or CRIT) to output from syslog-ng (optional - defaults to INFO)

page_size - number of results to return in a single page (optional - defaults to 100)

max_performance - Disables json parsing of message for timestamp extraction if True (optional - defaults to False)

initial_hours - number of hours to search backward on initial fetch (optional - defaults to 4)

ignore_persistence - If True, ignores the last time logs were fetched on startup and sets the search window initial_hours back

ssl_verify - It False, doesn't require valid SSL certificates for communication with RSA SecurID Cloud API access

fetch-no-data-delay - seconds to wait before attempting a fetch after no results are returned (optional, defaults to 60)

persist-name - a unique name for this driver (optional - defaults to rsa-securid-cloud-<url>-<log_type>)