# syslogng-proofpoint

Syslogng drivers for Proofpoint

## Purpose

This is a python syslogng.LogSource implementation designed to retrieve events from Proofpoint on Demand via [API](https://docs.cyderes.cloud/files/proofpoint-on-demand-log-api-rev-c.pdf) for ingestion by syslog-ng.

## Dependencies

This driver requires the Python websocket-client module to be available which is not included with syslog-ng PE. There are several ways to access it including:

Install the required modules directly into the syslog-ng PE installation

    /opt/syslog-ng/bin/python3 -m pip install websocket
	/opt/syslog-ng/bin/python3 -m pip install pytz

Use the base OS Python modules for syslog-ng by modifying plugin.conf for the correct local path:

    sys.path.append("/usr/lib/python3.8/site-packages/")

## Components

### proofpoint.py

This is the syslogng.LogSource implementation which can be configured as a standalone source in syslog-ng. To utilize the Proofpont-on-Demand driver, the following steps are needed:
1. Create a new SCL directory named hypr (e.g., /opt/syslog-ng/share/syslog-ng/include/scl/proofpoint/)
2. Save plugin.conf to /opt/syslog-ng/share/syslog-ng/include/scl/proofpoint/plugin.conf
3. Save proofpoint.py to /opt/syslog-ng/share/syslog-ng/include/scl/proofpoint/proofpoint.py
4. Create a new syslog-ng source with the required parameters
    
To configure the source, certain parameters are required:

    source s_proofpoint_message {
	    python(
		    class("proofpoint.ProofpointOnDemand")
		    options(
			    "cid","<The cluster ID license for the PPS deployment>"
			    "token","<base64 encoded authorization token>"
			    )
		    flags(no-parse)
	    );
    };


Additional options can also be specified:

    source s_proofpoint_message {
	    python(
		    class("proofpoint.ProofpointOnDemand")
		    options(
			    "cid","<The cluster ID license for the PPS deployment>"
			    "token","<base 64 encoded authorization token>"
			    "type","<message|maillog>" # optional - defaults to message
			    "backoff_time","<int seconds timer for retrying failed operations>" # optional - defaults to 10 seconds
			    "log_level","<DEBUG|INFO|WARN|ERROR>" # optional - defaults to INFO
			    "ssl_verify","<true|false>" # optional - defaults to requiring trusted SSL certificate
			    "max_performance","<true|false>" # optional - defaults to false
			    "backfill_hours","<number of hours back to retrieve events for>" # optional - defaults to 0
			    "backfill_start","<ISO 8601 timestamp in UTC for start of fetch window>" # optional
			    )
		    flags(no-parse)
		    persist-name(<unique name for driver>)
	    );
    };

Here are sample values as a reference:

    source s_proofpoint_message {
	    python(
		    class("proofpoint.ProofpointOnDemand")
		    options(
			    "companyname_hosted","<The cluster ID license for the PPS deployment>"
			    "token","xxxx"
			    "type","message" # optional - defaults to message
			    "30","<int seconds timer for retrying failed operations>" # optional - defaults to 10 seconds
			    "log_level","DEBUG" # optional - defaults to INFO
			    "ssl_verify","false" # optional - defaults to requiring trusted SSL certificate 
			    "max_performance","false" # optional - defaults to false
			    "backfill_hours","24" # optional - defaults to 0
			    "backfill_start","2022-08-01T15:45:59-0000" # optional
			    )
		    flags(no-parse)
		    persist-name(s_proofpoint_message)
	    );
    };

### Driver options

cid - The cluster ID license for the PPS deployment

token - base 64 encoded authorization token

type - whether to retrieve message or maillog entries from Proofpoint (optional, defaults to message)

backoff_time - number of seconds to wait before retrying a failed operation (optional, defaults to 10)

log_level - What level of logging to output (DEBUG, INFO, WARN, ERROR) from syslog-ng (optional, defaults to INFO)

ssl_verify - Whether or not to require trusted certificates (true or false) (optional - defaults to True)

max_performance - Disables json parsing of messages for extracting timestamp from an event for a very small performance gain if true (true|false) (optional - defaults to false)

backfill_hours - Retrieve events from the past backfill hours before now (or after backfill_start if specified) and then continue fetching events normally. **This option will create duplicate logs due to limitations in the Proofpoint PoD API**

backfill_start - An ISO 8601 formatted timestamp **in UTC** for when to start fetching logs. If backfill_start is specified and backfill_hours is not, the driver will fetch all logs from backfill_start to now and then fetch current logs (indefinitely). If backfill_start is specified and backfill_hours is specified, the driver will fetch all logs from backfill_start to backfill_start + backfill_hours **and then exit**. The timestamp format must be in the form of %Y-%m-%dT%H:%M:%S-0000 where **-0000** is required (only UTC timestamps are supported).


### Proofpoint-on-Demand API Limitations

During normal use, Proofpoint will send a very small number of duplicate events over time. When retrieving previous events (using backfill_start and/or backfill_hours), there is usually a significant increase in duplicate events being sent. The Proofpoint API only supports time based fetches at the hour granularity (rounded down to the nearest hour for start times and up to the nearest hour for end times). There is additionally an issue when performing time based fetches that end at the current time as Proofpoint will send overlapping (duplicate) events.  