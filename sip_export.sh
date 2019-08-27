#!/usr/bin/env bash

# use the default directory if not set
if [ ! -v DETECT_EXPORTS ];
then
    export DETECT_EXPORTS=/opt/detect_exports
fi

####################################################################################
##### Splunk Lookup Table Exports ##################################################
####################################################################################
cd "${DETECT_EXPORTS}" || exit 1
#Ashland
python3 sip_export_splunk.py -c etc/ashland_detect_export.ini
(cd "${DETECT_EXPORTS}/ashland_splunk_lookup_tables" && git add *.csv > /dev/null && git commit -m "automated commit $(date '+%Y%m%d%H%M%S')" > /dev/null && git push origin production > /dev/null )
#Valvoline
python3 sip_export_splunk.py -c etc/valvoline_detect_export.ini
(cd "${DETECT_EXPORTS}/valvoline_splunk_lookup_tables" && git add *.csv > /dev/null && git commit -m "automated commit $(date '+%Y%m%d%H%M%S')" > /dev/null && git push origin production > /dev/null )
#Integral
python3 sip_export_splunk.py -c etc/integral_detect_export.ini
(cd "${DETECT_EXPORTS}/integral_splunk_lookup_tables" && git add *.csv > /dev/null && git commit -m "automated commit $(date '+%Y%m%d%H%M%S')" > /dev/null && git push origin production > /dev/null )

cd "${DETECT_EXPORTS}"

##################################
