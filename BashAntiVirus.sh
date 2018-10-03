#!/bin/bash

# Your VirsuTotal API key can be pass as an argument or embeded in the script
api_key=${1}
ERROR=1
# Hashlist is the list of already retrive process information
# this reduce the need to ask VT for information only for never seen before process
HASHLIST="HashList"

function vt
{
    curl_response="$(curl -s --request GET --url "https://www.virustotal.com/vtapi/v2/file/report?apikey=${api_key}&resource=${1}" || exit_error 3)"
    while [ -z "${curl_response}" ]; do
        echo 'no response from API, waiting one minute...' >&2
        sleep 60
        curl_response="$(curl -s --request GET --url "https://www.virustotal.com/vtapi/v2/file/report?apikey=${api_key}&resource=${1}" || exit_error 3)"
    done
}

function vt_upload
{
    curl_response="$(curl -s --request POST --url 'https://www.virustotal.com/vtapi/v2/file/scan' --form "apikey=${api_key}" --form "file=@${1}")"
    while [ -z "${curl_response}" ]; do
        echo 'no response from API, waiting one minute..' >&2
        sleep 60
        curl_response="$(curl -s --request POST --url 'https://www.virustotal.com/vtapi/v2/file/scan' --form "apikey=${api_key}" --form "file=@${1}")"
    done
    if ! echo "${curl_response}" | grep -q 'come back later for the report'; then
        exit_error 4
    fi
}

for file_name in $(for pid in $(sudo find  /proc/ -maxdepth 2  -name exe);do   sudo readlink -f $pid;done | sort | uniq);
do
    #file_name=$(sudo readlink -f ${pid})
    #echo -n "filename: " ${file_name} " "
		if [ ! -f ${file_name} ];then
			#echo "file not found"
			continue
		fi
		file_hash=$(sha256sum ${file_name}|awk '{print $1}')
    #echo -n $sha " "
		if grep -q "${file_hash}" ${HASHLIST}; then
        curl_response=$(grep ${file_hash} ${HASHLIST})
				#echo "Already Found in the hashlist - no need to add it"
				#echo "${curl_response}" >> ${HASHLIST}
    else
	    vt ${file_hash}
	    if echo "${curl_response}" | grep -q 'The requested resource is not'; then
	        vt_upload ${file_name}
	        echo  "The requested resource was not found, ${file_name} has been uploaded, come back in an hour " >&2
					echo -n "${file_hash} ${file_name} # The requested resource was not found, ${file_name} has been uploaded, come back in an hour" >> ${HASHLIST}
	    else
					# Never seen before process - adding VT info to the HASHLIST for futur queries
	        echo -n "${file_hash} ${file_name} # " >> ${HASHLIST}
					echo -n "${curl_response}" | sed 's/\\\\\//\//g' | sed 's/[{}]//g' | awk -v k="text" '{n=split($0,a,","); for (i=1; i<=n; i++) print a[i]}' | sed 's/\"\:\"/\|/g' | sed 's/[\,]/ /g' | sed 's/\"//g' | grep -E 'positives:|scan_date:|total:' |tr '\n' ' ' >> ${HASHLIST}
	        curl_response=$(echo "${curl_response}" | sed 's/\\\\\//\//g' | sed 's/[{}]//g' | awk -v k="text" '{n=split($0,a,","); for (i=1; i<=n; i++) print a[i]}' | sed 's/\"\:\"/\|/g' | sed 's/[\,]/ /g' | sed 's/\"//g' | grep -E 'positives:|scan_date:|total:' |tr '\n' ' ')
					echo "" >> ${HASHLIST}
			fi
		fi
		if  echo "${curl_response}" | grep -qv "positives: 0"; then
			echo "Detection : ${curl_response}"
    	ERROR=0
    fi
done
if [ "$ERROR" = 1 ] ; then
    echo "All running process are mark as safe by all antivirus engine detection available on VT"
fi
