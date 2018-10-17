#!/bin/bash

# Your VirsuTotal API key can be pass as an argument or embeded in the script
api_key=${1}
ERROR=1
TIMEOUT=5
# Hashlist is the list of already retrive process information
# this reduce the need to ask VT for information only for never seen before process
HASHLIST=${2}
# if VT is not accessible, fallback only on local hash list
LOCALONLY=0
NEVERSENDMYBINARY=1

function vt
{
	if [ "${LOCALONLY}" = 0 ]; then
    curl_response="$(curl -s --connect-timeout ${TIMEOUT} --request GET --url "https://www.virustotal.com/vtapi/v2/file/report?apikey=${api_key}&resource=${1}")"
		retVal=$?
		if [ $retVal -ne 0 ]; then
    	LOCALONLY=1
			curl_response="network connection timeout"
			return $?
		fi
		while [ -z "${curl_response}" ]; do
        echo 'no response from API, waiting one minute...' >&2
        sleep 60
        curl_response="$(curl -s --connect-timeout ${TIMEOUT} --request GET --url "https://www.virustotal.com/vtapi/v2/file/report?apikey=${api_key}&resource=${1}")"
    done
	else
		curl_response="network connection forbiden or not possible : LOCALONLY ${LOCALONLY}"
	fi
}

function vt_upload
{
		if [ "${LOCALONLY}" = 0 ] || [ "${NEVERSENDMYBINARY}" = 0 ]  ; then
			read -p "Do you want to upload ${1} to virustotal ? [y/N]" -n 1 -r
			if [[ $REPLY =~ ^[Yy]$ ]]
			then
	    	curl_response="$(curl -s --connect-timeout ${TIMEOUT} --request POST --url 'https://www.virustotal.com/vtapi/v2/file/scan' --form "apikey=${api_key}" --form "file=@${1}")"
	    	while [ -z "${curl_response}" ]; do
	        	echo 'no response from API, waiting one minute..' >&2
		        sleep 60
		        curl_response="$(curl -s --connect-timeout ${TIMEOUT} --request POST --url 'https://www.virustotal.com/vtapi/v2/file/scan' --form "apikey=${api_key}" --form "file=@${1}")"
		    done
		    if ! echo "${curl_response}" | grep -q 'come back later for the report'; then
		        return 4
		    fi
			fi
		else
			curl_response="network connection forbiden : LOCALONLY ${LOCALONLY} , NEVERSENDMYBINARY ${NEVERSENDMYBINARY}"
		fi
}

for file_name in $(for pid in $(sudo find  /proc/ -maxdepth 2  -name exe);do   sudo readlink -f $pid;done | sort | uniq);
do
    #file_name=$(sudo readlink -f ${pid})
    #echo -n "filename: " ${file_name} " "
		if [ ! -f ${file_name} ];then
			#echo "file not found, continue to next binary..."
			continue
		fi
		file_hash=$(sudo /bin/cat ${file_name} | sha256sum ${file_name}|awk '{print $1}')
    #echo -n $sha " "
		if grep -q "${file_hash}" ${HASHLIST}; then
        curl_response=$(grep ${file_hash} ${HASHLIST})
				#echo "Already Found in the hashlist - no need to add it"
    else
				#echo 'not in local hash , perform a query to VT'
		    vt ${file_hash}
		    if echo "${curl_response}" | grep -q 'The requested resource is not'; then
						# VT has no info, uploading sample
		        vt_upload ${file_name}
						echo  "${file_hash} ${file_name} # The requested resource was not found, ${file_name} has been uploaded, come back in an hour" >&2
		  	elif echo "${curl_response}" | grep -q "Scan finished, information embedded"; then
				# echo 'curl_response contain raw VT reply'
						# Never seen before process - adding VT info to the HASHLIST for futur queries
		        echo -n "${file_hash} ${file_name} # " >> ${HASHLIST}
						echo -n "${curl_response}" | sed 's/\\\\\//\//g' | sed 's/[{}]//g' | awk -v k="text" '{n=split($0,a,","); for (i=1; i<=n; i++) print a[i]}' | sed 's/\"\:\"/\|/g' | sed 's/[\,]/ /g' | sed 's/\"//g' | grep -E 'positives:|scan_date:|total:' |tr '\n' ' ' >> ${HASHLIST}
						echo "" >> ${HASHLIST}
						curl_response=$(echo "${curl_response}" | sed 's/\\\\\//\//g' | sed 's/[{}]//g' | awk -v k="text" '{n=split($0,a,","); for (i=1; i<=n; i++) print a[i]}' | sed 's/\"\:\"/\|/g' | sed 's/[\,]/ /g' | sed 's/\"//g' | grep -E 'positives:|scan_date:|total:' |tr '\n' ' ')
				elif echo "${curl_response}" | grep -q "network connection "; then
					# network connection impossibl
					#echo "${file_name} is not in local HashList and ${curl_response}" >> ${HASHLIST}
					curl_response=$(echo "${file_hash} ${file_name} is not in local HashList and ${curl_response}" )
				else
					# WTF
						#echo "${file_name} unknown errors while analsing  " >> ${HASHLIST}
						curl_response=$(echo "${file_name} unknown errors while analsing" )
				fi
			if  echo "${curl_response}" | grep -qv "positives: 0"; then
					echo "Detection : ${curl_response}"
	    		ERROR=0
	    fi
		fi
done
if [ "$ERROR" = 1 ] ; then
    echo "All running process are mark as safe by all antivirus engine detection available on VT"
fi
