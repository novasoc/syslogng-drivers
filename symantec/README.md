# syslogng-symantec

## Purpose

This is a python syslogng.LogFetcher implementation designed to fetch events from Symantec WSS via their [API](https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/web-security-service/help/wss-api/report-sync-about.html/) for ingestion by syslog-ng.

## Dependencies

This driver requires the Python pytz module to be available which is not included with syslog-ng PE. There are several ways to access it including:

Install the required modules directly into the syslog-ng PE installation

	/opt/syslog-ng/bin/python3 -m pip install pytz

Use the base OS Python modules for syslog-ng by modifying plugin.conf for the correct local path:

    sys.path.append("/usr/lib/python3.8/site-packages/")

## Components

### symantec.py

This is the syslogng.LogSource implementation which can be configured as a standalone source in syslog-ng. To utilize the Symantec WSS driver, the following steps are needed:
1. Create a new SCL directory named hypr (e.g., /opt/syslog-ng/share/syslog-ng/include/scl/symantec/)
2. Save plugin.conf to /opt/syslog-ng/share/syslog-ng/include/scl/symantec/plugin.conf
3. Save symantec.py to /opt/syslog-ng/share/syslog-ng/include/scl/symantec/symantec.py
4. Create a new syslog-ng source with the required parameters
    
To configure the source, certain parameters are required:

    source s_symantec_wss {
	    python(
		    class("symantec.WSS")
		    options(
			    "username","<Username for authentication to Symantec WSS>"
			    "password","<base64 encoded password>"
			    )
		    flags(no-parse) # required as these aren't syslog messages
            fetch-no-data-delay(<seconds to pause between fetches>)  # required and must be > 60 but defaults to global value of time-reopen
	    );
    };


Additional options can also be specified:

    source s_symantec_wss {
	    python(
		    class("symantec.WSS")
		    options(
			    "username","<Username for authentication to Symantec WSS>"
			    "password","<base64 encoded password>"
			    "buffer_dir","<directory to temporarily store downloaded archives>" # optional - defaults to /tmp
			    "log_level","<DEBUG|INFO|WARN|ERROR>" # optional - defaults to INFO
			    "initial_hours","<number of hours back to start retrieving events for>" # optional - defaults to 0
			    "timeout","<number of seconds before an HTTP download times out>" # optional - defaults to 900
			    "extract_hostnames","<true|false>" # optional - will extract hostname for syslog hostname field - defaults to true
			    "key_values","<true|false>" # optional - converts log entries to key-value pairs - defaults to true
			    )
		    flags(no-parse) # required as these aren't syslog messages
		    fetch-no-data-delay(<seconds to pause between fetches>) # required and must be > 60 but defaults to global value of time-reopen
	    );
    };

Here are sample values as a reference:

    source s_symantec_wss {
	    python(
		    class("symantec.WSS")
		    options(
			    "username","1234abc-1234-abcd-1234"
			    "password","GSDFgkjhs46g59sdfG2vfa"
			    "buffer_dir","/tmp/wss" # optional - defaults to /tmp
			    "log_level","info" # optional - defaults to INFO
			    "initial_hours","0" # optional - defaults to 0
			    "timeout","600" # optional - defaults to 900
			    "extract_hostnames","true" # optional - will extract hostname for syslog hostname field - defaults to true
			    "key_values","false" # optional - converts log entries to key-value pairs - defaults to true
			    )
		    flags(no-parse) # required as these aren't syslog messages
		    fetch-no-data-delay(300)
	    );
    };

### Driver options

**username** - The username to authenticate to Symantec WSS

**password** - Base 64 encoded password for the above username

buffer_dir - Directory for uncompressing downloaded archives (which can be very large) for processing temporarily (optional, defaults to /tmp)

log_level - What level of logging to output (DEBUG, INFO, WARN, ERROR) from syslog-ng (optional, defaults to INFO)

timeout - Download archives can reach over 1 GB and take significant time to download. In some cases the connection can permanently stall though so a timeout is necessary to prevent the driver from hanging. (optional - defaults to 900 seconds)

initial_hours - Retrieve events from the past initial_hours before now and then continue fetching events normally. **On first run the driver will start at the previous hour boundary as the API requires an hour boundary for fetch windows**

extract_hostnames - Extract the hostname from an event for the syslog hostname field (optional - defaults to true)

key_values - Use the headers from the downloaded logs to create key-value pairs for each log entry and use the key-value pairs as the logs instead of the raw logs (optional - defaults to true)

**fetch-no-data-delay** - This option must be enabled for a **minimum of 60 seconds** although higher values are recommended to avoid being blocked by Symantec WSS for having too aggressive of a client. As the API isn't meant for realtime streaming, too many queries in a short amount of time will trigger a response. This is a standard syslog-ng configuration option and not a driver specific option.

### Symantec WSS API Limitations

The Symantec WSS API allows for downloading events in near real-time or historical events. The results are returned in one more more gziped text files contained within a zip file. This driver will first download the zip containing the requested events and then process each archive for log extraction. The zip/gzip contents can be quite large when uncompressed so ensuring there is sufficient storage available under buffer_dir is important.

In some environments, the performance of the syslog-ng Python driver may be insufficient, particularly when performing long term historical fetches. In this case, using the log_dir option will tell the driver to fetch and uncompress all log data to log_dir but not process the entries. The driver will never return a new event in this configuration and instead requires use of the wildcard-file driver to ingest the downloaded content (and other solutions like logrotate to delete the downloaded content).

### Python driver limitations

Depending on the version of Python used, there may be memory leaks in list handling that can contribute to significant memory utilization when running the driver with large fetch windows (time based fetches or after long outages). After each event is processed it is removed from the internal list of events but due to certain list implementations, this memory is never freed (although it will be reused). A similar problem can occur during syslog-ng reload events where the original list isn't freed but a new one is created. 