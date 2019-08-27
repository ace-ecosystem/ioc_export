#!/usr/bin/env bash

# use the default directory if not set
if [ ! -v DETECT_EXPORTS ];
then
    export DETECT_EXPORTS=/opt/detect_exports
fi

####################################################################################
##### CSV / Splunk Lookup Table Exports ##################################################
####################################################################################
cd "${DETECT_EXPORTS}" || exit 1

python3 crits_export_splunk.py -c etc/detect_export.ini
(cd "${DETECT_EXPORTS}/splunk_lookup_tables" && git add *.csv > /dev/null && git commit -m "automated commit $(date '+%Y%m%d%H%M%S')" > /dev/null && git push origin production > /dev/null )

cd "${DETECT_EXPORTS}"

python3 crits_export_ssdeep.py -c etc/detect_export.ini
(cd "${DETECT_EXPORTS}/crits_ssdeep" && git add *.json > /dev/null && git commit -m "automated commit $(date '+%Y%m%d%H%M%S')" > /dev/null && git push origin production > /dev/null )

####################################################################################
##### Yara Rule Intel Exports     ##################################################
####################################################################################

if [ ! -e YARA_COMPILE_ERROR ]
then
    python3 crits_export_yara.py -c etc/detect_export.ini

    # make sure the yara rules compile
    if ! /usr/local/bin/scan -c -Y crits_yara_rules
    then
        # if they don't then let us know and don't try again until they are fixed
        echo 'ERROR compiling crits yara rules'
        /usr/local/bin/scan -c -Y crits_yara_rules | mailx -r monitoring@fqdn.com -s 'crits yara exports have a syntax error' monitoring@fqdn.com
        echo 'ERROR: make sure you delete this file after you fix the error' > YARA_COMPILE_ERROR
        exit 1
    fi

    ( cd "${DETECT_EXPORTS}/crits_yara_rules" && git add *.yar > /dev/null && git commit -m "automated commit $(date '+%Y%m%d%H%M%S')" > /dev/null && git push origin production > /dev/null )
else
    echo "YARA_COMPILE_ERROR!!!"
fi
