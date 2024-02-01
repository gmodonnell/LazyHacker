#!/bin/bash
# Recon Automation for Internal/External Network Penetration Tests

# Drip Comes First...
RED="\e[91m"
GREEN="\e[92m"
# ORANGE
O='\e[38;5;214m'
# BROWN
B='\e[38;5;130m'
U='\e[38;5;51m'
# YELLOW
Y='\e[38;5;220m'
# RESET COLOR
RC='\e[39m'

function logo () {
echo -e "
                                                                 
	${Y}:dddd,.                                                               
	 .oooOOoo:.                                                           
	     .ooOOOoo..                                                      
        	..loxkO'${B}:${Y}odc                                                 
	            ...${B}::${Y}OOOOOkl;.                                            
         	        ${B}'${Y}0OOOOOOOOOOOd${B}..${Y}                                       
                	 .ok000OOOOkc${B}::${Y}OOdc'                                  
	                    .coxxxOO${B}::${Y}OOOOOOOklc:c,                           
        	                .'.${B}::${Y}OOOOOOOOOOOOOdl${B}..${Y}                        
                	           ${B}::${Y}OOOOOOOOOOOOOO${B}::${Y}oxxo;.                  
                        	    ${B}:${Y}okOOOOOOOOOOl${B}:::${Y}OOOOOOOOxc,.             
                                	:dkkOOOOO${B}:::${Y}OOOOOOOOOOk${B}odocc;${Y}.        
	                                   ,;co${B}:::${Y}OOOOOOOOOOo${B}:oOOl${Y}coddxo:.    
        	                               ${B}:${Y}OOOOOOOOOx,${B}oOk:${Y}c0Oolc:;,lO;  
              ${RED}Recon Enthusiast${Y}                 :OOOOOOOOx.${B}kOo${Y}'00${U}cokkkxo${Y};' do 
                 v1.3 - for ${U}Maltek Solutions${Y}      'ddkxOO.${B}dOx${Y}.Xk${U}ckkkkkkkx${Y}:, 0
                                	             .,,c ${B}OO'${Y}dN${U};kkkkkkkkk${Y} : k
                                        	        . ${B}lk.${Y}kN${U},kkkkkkkk${Y},;. 0 
                                                	  ${B} ..${Y};N${U}cokkkkko${Y},,..O  
	                                                    ${B} .${Y}cXl${U},:c:'${Y}...ll   
        	                                                ckkdlooo      
                                                            
"
}

#Pre-Flight Checklist
logo
if [ -f "scope" ]; then 
	: 
else 
	echo -e "${RED}No SCOPE... Aborting ${RC}"
	exit 1
fi
if [ "$EUID" -ne 0 ]; then
	echo -e "${RED}Need SUDO... Aborting ${RC}"
	exit 1
fi
if [ $(dpkg-query -W -f='${Status}' sslscan 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
	echo -e "${RED}sslscan NOT installed via apt... Aborting ${RC}"
	exit 1
elif [ $(dpkg-query -W -f='${Status}' ssh-audit 2>/dev/null | grep -c "ok installed") -eq 0 ]; then 
	echo -e "${RED}ssh-audit NOT installed via apt... Aborting ${RC}"
	exit 1
elif [ $(dpkg-query -W -f='${Status}' jq 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
	echo -e "${RED}jQuery NOT installed via apt... Aborting ${RC}"
	exit 1
fi


function dehashQuery () {
	login=""
	apikey=""
	echo -e "${GREEN}Argument Provided: Querying Dehashed for $searchTerm${RC}"
	# cURL API Request, send to json file
	curl "https://api.dehashed.com/search?query=email:"@$searchTerm"&size=10000" -u $login:$apikey -H 'Accept: application/json' > curledData.json
	# Parse Everything Out Using jQuery
	curLength=$(cat curledData.json | jq '.entries | length')
	index=0
	echo "$curLength records to parse. Starting Now..."
	for item in $(cat curledData.json | jq -c '.entries[]' 2>/dev/null); do
		echo -ne "$index/$curLength\r"
		email=$(echo "${item}" | jq -r '.email' 2>/dev/null)
		password=$(echo "${item}" | jq -r '.password' 2>/dev/null)
		hashed_password=$(echo "${item}" | jq -r '.hashed_password' 2>/dev/null)
		database_name=$(echo "${item}" | jq -r '.database_name' 2>/dev/null)
		if [ -n "$password" ] || [ -n "$hashed_password" ]; then
			if [ -z "$email" ] || [ -z "$database_name" ]; then
				echo "Skipping Empty Entry. Reason: No DB or Email"
				continue
			else
				echo "$email,$password,$hashed_password,$database_name" >> dehashedResults.csv
				((index++))
			fi
		fi
	done
	cat dehashedResults.csv | sort | uniq -u > dehashedCleaned.csv
	awk -F', ' '!seen[$1,$2,$3]++' "dehashedCleaned.csv" > dehashedDeduped.csv
}

# =================== PARSEFUNCS ===================
#  All the Nmap Parsing Functionality from Shifty0g
# ==================================================

function mastercleanup () {
# MASTER cleanup - lazy just to wipe the temp stuff before and after so all fresh
rm "${outpath}tempinput" "${outpath}ipptemp" "${outpath}closedtemp" "${outpath}summtemp" "${outpath}tempfile" "${outpath}tempfile2" "${outpath}$varTempFile2" "${outpath}inputfile" "${outpath}$varTempFile" "${outpath}$tempfile" "${outpath}$varSummTempFile" "${outpath}webtemp" "${outpath}webtemp2" "${hostportspath}hostptemp" "${outpath}temp.gnmap" "${outpath}temp.csv" "${outpath}sshtemp"> /dev/null 2>&1
}

makecsv () { 
echo -e "\e[1m\e[93m[>]\e[0m Creating CSV File"
while read line; do
        checkport=$(echo $line | grep -e '/open/' -e '/closed')
        if [ "$checkport" != "" ]; then
                host=$(echo $line | awk '{print $2}')
                lineports=$(echo $line | awk '{$1=$2=$3=$4=""; print $0}')
                if [ -f "${outpath}"tempfile2"" ]; then rm "${outpath}"tempfile2""; fi
                echo "$lineports" | tr "," "\n" | sed 's/^ *//g' >> "${outpath}"tempfile2""
                # Read the per-host temp file to write each open port as a line to the CSV temp file
                while read templine; do
                # check for open port
                checkport2=$(echo $templine | grep -e '/open/' -e '/closed')
                if [ "$checkport2" != "" ]; then
                        port=$(echo $templine | awk -F '/' '{print $1}')
                        status=$(echo $templine | awk -F '/' '{print $2}')
                        protocol=$(echo $templine | awk -F '/' '{print $3}')
                        service=$(echo $templine | awk -F '/' '{print $5}')
                        version=$(echo $templine | awk -F '/' '{print $7}')
                        echo "$host,$port,$status,$protocol,$service,$version" >> "${outpath}temp.csv"
                fi
                done < "${outpath}tempfile2"
        fi
done < "${outpath}temp.gnmap" 
# finalise and move the file if temp.csv
if [ -f "${outpath}temp.csv" ]; then
   echo "HOST,PORT,STATUS,PROTOCOL,SERVICE,VERSION" > "${outpath}parsed_nmap.csv" 
   # sort by ip address - 1st.2nd.3rd.4th
   cat "${outpath}"temp.csv"" |  sort -u | sort -t"," -n -k1 | sort -V >> "${outpath}parsed_nmap.csv" 
   echo "       - parsed_nmap.csv"
fi
#cleanup 
rm "${outpath}temp.csv" "${outpath}"tempfile2"" > /dev/null 2>&1
}

checkcsv () {
# checks if the makecsv function has already ran and then sets the tempfile varible - stops repetition as most other functions use the csv file 
cp "${outpath}parsed_nmap.csv" "${outpath}temp.csv"
# remove the head from the csv file 
sed -i -e "1d" "${outpath}temp.csv"
# remove lines that have closed ports 
sed -i '/,closed,/d' "${outpath}temp.csv"
export tempfile="$(realpath "${outpath}temp.csv")"
}

summary () {
# creates the summary file of from the input of open ports
echo -e "\e[1m\e[93m[>]\e[0m Creating Summary"
#check for csv file to process
checkcsv
#clear any old file - fresh
rm "${outpath}summary.txt" > /dev/null 2>&1
echo "+=========================================================================================+" >> "${outpath}summary.txt"
printf "%-18s %-16s %-52.52s %-2s \n" "| HOST " "| PORT / PROTOCOL" " | SERVICE" "|" >> "${outpath}summary.txt"
lasthost=""
while read line; do
        host=$(echo $line | awk -F ',' '{print $1}')
        port=$(echo $line | awk -F ',' '{print $2}')
        protocol=$(echo $line | awk -F ',' '{print $4}')
        service=$(echo $line | awk -F ',' '{print $5}')
        version=$(echo $line | awk -F ',' '{print $6}')
        if [ "$host" != "$lasthost" ]; then echo "+=========================================================================================+" >> "${outpath}summary.txt"; fi
        if [ "$version" = "" ]; then
                version=""
        else
                version="- $version"
        fi
        printf "%-18s %-16s %-52.52s %-2s \n" "| $host " "| $port / $protocol " "  | $service $version" " |" >> "${outpath}summary.txt"
        lasthost="$host"
done < "$tempfile"
echo "+=========================================================================================+" >> "${outpath}summary.txt"
echo "  - summary.txt"
echo
#cleanup
rm  "$tempfile" > /dev/null 2>&1
#end
}

ipport () {
# creates a file of open ports IP:PORT
echo -e "\e[1m\e[93m[>]\e[0m Creating IP Port file "
# check is csv is run and get a tempfile
checkcsv
#clear any old file - fresh
rm "${outpath}ipport.txt" > /dev/null 2>&1
# finalise the file and clean up
cat "$tempfile"  | cut -d, -f1,2 | tr -d '"' | tr , : | sort -V > "${outpath}ipport.txt"
#cleanup
rm  "$tempfile" > /dev/null 2>&1
echo "  - ipport.txt"
}

uphosts () {
# creates a file with IPs for hosts with Up Statues - needs further checks to be better 
echo -e "\e[1m\e[93m[>]\e[0m Parsing up hosts"
cat "$inputfilepath" | grep -e 'Status: Up' -e '/open/' |  awk '{ print $2 }' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u -V  > "$outpath/up.txt" 

# check if there are actually any IP addresses in the file - if not delete it no point 
if [ -z "$(cat "${outpath}up.txt" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")" ]
then
          echo -e "$RED - no up hosts $RESETCOL"
          rm "${outpath}up.txt" > /dev/null 2>&1
else
      echo "    - up.txt"
fi
echo
}

downhosts () {
# creates a file with IPs for hosts with Down status 
echo -e "\e[1m\e[93m[>]\e[0m Parsing down hosts"
cat "$inputfilepath" | grep -e 'Status: Down' | awk '{ print $2 }' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u -V > "${outpath}down.txt"
# check if there are actually any IP addresses in the file - if not delete it no point 
if [ -z "$(cat "${outpath}down.txt" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")" ]
then
      echo -e "$RED     - no down hosts $RESETCOL"
          rm "${outpath}down.txt" > /dev/null 2>&1
else
      echo "    - down.txt"
fi
}

function uniqueports () {
echo -e "\e[1m\e[93m[>]\e[0m Parsing unique ports"
cat "$inputfilepath" | grep -o -P '.{0,9}/open/' | awk '{ print $2}' | cut -d /  -f 1 | sort -u -V | paste -s -d, 2>&1 > "${outpath}unique.txt"; 
if [ -z "$(cat "${outpath}unique.txt" | grep '[0-9]')" ]
then
          echo -e "$RED - no Unique ports $RESETCOL"
          rm "${outpath}unique.txt" > /dev/null 2>&1
else
      echo "    - unique.txt"
fi
}

tcpports () {
# creates a file of unqiue open TCP ports - 22,23,80,443...
echo -e "\e[1m\e[93m[>]\e[0m Parsing tcp ports"
cat "$inputfilepath" | grep '/tcp/' | grep -o -P '.{0,9}/open/' | awk '{ print $2}' | cut -d /  -f 1 | sort -u -V | paste -s -d, 2>&1 > "${outpath}tcp.txt";

# check for a number if the file has them then likely has ports in
if [ -z "$(cat "${outpath}tcp.txt" |  grep '[0-9]')" ]
then
          echo -e "$RED - no TCP ports $RESETCOL"
          rm "${outpath}tcp.txt" > /dev/null 2>&1
else
      echo "    - tcp.txt"
fi
}

udpports () {
# creates a file of unqiue open UDP ports - 53,161...
echo -e "\e[1m\e[93m[>]\e[0m Parsing udp ports"
cat "$inputfilepath" | grep '/udp/'  | grep -o -P '.{0,9}/open/' | awk '{ print $2}' | cut -d /  -f 1 | sort -u -V | paste -s -d, 2>&1 > "${outpath}udp.txt"
# check for a number if the file has them then likely has ports in
if [ -z "$(cat "${outpath}udp.txt" | grep '[0-9]')" ]
then
          echo -e "$RED - no UDP ports $RESETCOL"
          rm "${outpath}udp.txt" > /dev/null 2>&1
else
      echo "    - udp.txt"
fi
}

smb () {
# createa file for URI smb://192.168.1.1 
# will only grab out OPEN 445 TCP 
echo -e "\e[1m\e[93m[>]\e[0m Creating smb paths"
cat "$inputfilepath" | grep '445/open/tcp/' | awk '{ print $2}' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sed -e 's/^/smb:\/\//' | sort -u | sort -V | sort -t'/' -k2 -V  > "${outpath}smb.txt"
# check for a smb:// if the file has them then likely has ports in  
if [ -z "$(cat "${outpath}smb.txt" | grep 'smb://')" ]
then
        echo -e "$RED   - no SMB ports $RESETCOL"
        rm "${outpath}smb.txt" > /dev/null 2>&1
else
        echo "  - smb.txt"
fi
echo
}

web () {
# make a file of URLS to use with tools like nikto wafwoof est
echo -e "\e[1m\e[93m[>]\e[0m Creating web URLS"
# start fresh
rm "${outpath}$webfinalname" "${outpath}webtemp2"  > /dev/null 2>&1
#check that the csv file has been created
checkcsv
for line in $(cat "$tempfile"); do
        host=$(echo $line | awk -F ',' '{print $1}')
        port=$(echo $line | awk -F ',' '{print $2}')
        service=$(echo $line | awk -F ',' '{print $5}')
        version=$(echo $line | awk -F ',' '{print $6}')
        # a little overboard with the checks just to make sure all web ports are collected
        if [ "$port" = "80" ]; then echo "http://${host}:$port/" >> "${outpath}webtemp2"; fi
        if [ "$port" = "443" ]; then echo "https://${host}:$port/" >> "${outpath}webtemp2"; fi
        if [ "$port" = "8080" ]; then echo "http://${host}:$port/" >> "${outpath}webtemp2"; fi
        if [ "$port" = "8443" ]; then echo "https://${host}:$port/" >> "${outpath}webtemp2"; fi
        if [ "$service" = "http" ]; then echo "http://${host}:$port/" >> "${outpath}webtemp2"; fi
        if [[ "$service" == *"ssl"* ]]; then echo "https://${host}:$port/" >> "${outpath}webtemp2"; fi
        if [[ "$version" == *"Web"* ]]; then echo "http://${host}:$port/" >> "${outpath}webtemp2"; fi
        if [[ "$version" == *"web"* ]]; then echo "http://${host}:$port/" >> "${outpath}webtemp2"; fi
done
# if webtemp2 exists then sort it 
if [ -f "${outpath}webtemp2" ]; then
        sort -u "${outpath}webtemp2" | sort -V | sort -t'/' -k2 -V  > "${outpath}web.txt" 2>&1
        echo "  - web.txt"
else
        echo -e "$RED   - no ports found $RESETCOL"
        rm "${outpath}web.txt" > /dev/null 2>&1
fi
#cleanup
rm "${outpath}webtemp2" "$tempfile"  > /dev/null 2>&1
}

function ssl () {
echo -e "\e[1m\e[93m[>]\e[0m Creating ssl/tls list"
rm "${outpath}ssl.txt" "${outpath}ssltemp2" > /dev/null 2>&1
checkcsv
for line in $(cat "$tempfile"); do
        host=$(echo $line | awk -F ',' '{print $1}')
        port=$(echo $line | awk -F ',' '{print $2}')
        service=$(echo $line | awk -F ',' '{print $5}')
        version=$(echo $line | awk -F ',' '{print $6}')
        # a little overboard again - just to get anything with ssl or tls in 
        if [[ "$port" -eq "443" ]]; then echo "${host}:$port" >> "${outpath}ssltemp2"; fi
        if [[ "$service" == *"ssl"* ]]; then echo "${host}:$port" >> "${outpath}ssltemp2"; fi
        if [[ "$version" == *"ssl"* ]]; then echo "${host}:$port" >> "${outpath}ssltemp2"; fi
        if [[ "$service" == *"tls"* ]]; then echo "${host}:$port" >> "${outpath}ssltemp2"; fi
        if [[ "$version" == *"tls"* ]]; then echo "${host}:$port" >> "${outpath}ssltemp2"; fi

done
# if webtemp2 exists then sort it 
if [ -f "${outpath}ssltemp2" ]; then
        sort -u "${outpath}ssltemp2" | sort -V > "${outpath}ssl.txt" 2>&1
        echo "  - ssl.txt"
else
        echo -e "$RED   - no ports found $RESETCOL"
        rm "${outpath}ssl.txt" > /dev/null 2>&1
fi
rm "${outpath}ssltemp" "${outpath}ssltemp2" "$tempfile" > /dev/null 2>&1
}

ssh () {
echo -e "\e[1m\e[93m[>]\e[0m Creating ssh list"
rm "${outpath}ssh.txt" "${outpath}sshtemp" > /dev/null 2>&1
checkcsv
for line in $(cat "$tempfile"); do
        host=$(echo $line | awk -F ',' '{print $1}')
        port=$(echo $line | awk -F ',' '{print $2}')
        service=$(echo $line | awk -F ',' '{print $5}')
        version=$(echo $line | awk -F ',' '{print $6}')
        
        if [[ "$port" -eq "22" ]]; then echo "${host}:${port}" >> "${outpath}sshtemp"; fi
        if [[ "$service" == *"ssh"* ]]; then echo "${host}:${port}" >> "${outpath}sshtemp"; fi
        if [[ "$version" == *"ssh"* ]]; then echo "${host}:${port}" >> "${outpath}sshtemp"; fi
done
if [ -f "${outpath}sshtemp" ]; then
        sort -u "${outpath}sshtemp" | sort -V > "${outpath}ssh.txt" 2>&1
        echo "  - ssh.txt"
else
        echo -e "$RED   - no ports found $RESETCOL"
        rm "${outpath}ssh.txt" > /dev/null 2>&1
fi
rm "${outpath}sshtemp" "$tempfile" > /dev/null 2>&1
}

hostports () {
echo -e "\e[1m\e[93m[>]\e[0m Generating host port files"
rm "${outpath}hosts" -rf > /dev/null 2>&1
mkdir "${outpath}hosts" > /dev/null 2>&1
hostportspath=$(realpath "${outpath}hosts")
checkcsv
# loop through and Create split hosts files for each protocol
for line in $(cat "$tempfile"); do
        host=$(echo $line | awk -F ',' '{print $1}')
        port=$(echo $line | awk -F ',' '{print $2}')
        proto=$(echo $line | awk -F ',' '{print $4}')
        service=$(echo $line | awk -F ',' '{print $5}' | tr -d '-' | tr -d '?' | tr -d '|' )
        printout="Y"
        if [ "$port" == 445 ]; then
                service="smb"
        elif [ "$port" == 161 ]; then
                service="snmp"                  
        elif [ "$port" == 25 ]; then
                service="smtp"  
        elif [ "$port" == 21 ]; then
                service="ftp"   
        elif [ "$port" == 2049 ]; then
                service="nfs"
        elif [ "$port" == 22 ]; then
                service="ssh"
        elif [ "$port" == 23 ]; then
                service="telnet"
        elif [ "$port" == 111 ]; then
                service="rpc"
        elif [ "$port" == 137 ]; then
                service="netbios"
        elif [ "$port" == 139 ]; then
                service="netbios"
        elif [ "$port" == 3389 ]; then
                service="rdp"
        elif [ "$port" == 53 ]; then
                service="dns"                   
        elif [ "$port" == 113 ]; then
                service="ident"
        elif [ "$port" == 79 ]; then
                service="finger"
        elif [ "$port" == 5432 ]; then
                service="postgres"      
        elif [ "$port" == 3306 ]; then
                service="mysql"
        elif [ "$port" == 1433 ]; then
                service="mssql"                 
        elif [ "$port" == 443 ]; then
                service="https"
	elif [ "$port" == 80 ]; then
                service="http"
        elif [ "$port" == 636 ]; then
                service="ldap"  
        elif [ "$proto" == "udp" ] && [ "$port" == 161 ]; then
                service="snmp"  
        elif [ "$proto" == "udp" ] && [ "$port" == 177 ]; then
                service="xdmcp" 
        elif [ "$service" == "msrpc" ]; then
                # dont print out msrpc ..pointless - stop the spam
                printout="N"    
        elif [ "$proto" == "udp" ] && [ "$service" == "unknown" ]; then
                # dont udp + unknown ... cant really do much with this - stop spam
                printout="N"            
        elif [ -z "$service" ]; then
                # dont udp + unknown ... cant really do much with this - stop spam
                printout="N"    
        fi
        # print out the IP in port files
        if [ "$printout" == "Y" ]; then
                echo $host >> "$hostportspath"/"$proto"_"$port-$service.txt"            
        fi      
done
rm  "${hostportspath}/_-.txt" "$tempfile" > /dev/null 2>&1
echo "  - "${outhostsdir}"/[PROTOCOL]_[PORT]-[SERVICE].txt"
}

closedsummary() {
echo -e "\e[1m\e[93m[>]\e[0m Generating Closed Ports Summary"
rm "${outpath}closed-summary.txt" > /dev/null 2>&1
for host in $(cat "$inputfilepath" | grep "Host:" | grep "\/closed\/" | awk '{ print $2}'| sort --unique); do # will go through each host
    echo "Closed Ports For Host: $host " >> "${outpath}closed-summary.txt"
        echo -n "       " >> "${outpath}closed-summary.txt"
    for port in $(cat "$inputfilepath" | grep -w $host | grep -o -P '.{0,10}/closed/' | awk '{ print $2}' | cut -d /  -f 1 | sort --unique); do # go through ports
                echo -n $port", " >> "${outpath}closed-summary.txt"
    done # end ports loop
        echo -e "\n " >> "${outpath}closed-summary.txt"
done # end hosts loop
echo "  - "closed-summary.txt
}

report1() {
echo -e "\e[1m\e[93m[>]\e[0m Generating Report1"
rm "${outpath}report1.txt" "${outpath}"reportemp"" > /dev/null 2>&1
for host in $(cat $inputfilepath | grep "Host:" | grep "\/open\/" | awk '{ print $2}'| sort --unique); do # will go through each host
    echo -n $host  "[" >> "${outpath}"reportemp""
    for port in $(cat $inputfilepath | grep -w $host | grep -o -P '.{0,10}/open/' | awk '{ print $2}' | cut -d /  -f 1 | sort --unique); do # go through ports
                echo -n $port", " >> "${outpath}"reportemp""
    done # end ports loop
    echo  "]" >> "${outpath}"reportemp""
done # end hosts loop
cat "${outpath}"reportemp"" | sort -V | grep -v "\[\]"  >  "${outpath}report1.txt"
echo "  - "report1.txt
}

nmapparse () {
mastercleanup
cat "$(realpath nmap_scan.gnmap)" | sort -V >> temp.gnmap
export outpath="$(realpath scanparse)/"
mkdir scanparse > /dev/null 2>&1
mv temp.gnmap scanparse
export inputfilepath="$(realpath "scanparse/temp.gnmap")"
makecsv
summary
ipport
uniqueports
tcpports
udpports
uphosts
downhosts
smb
web
ssl
ssh
hostports
closedsummary
report1
mastercleanup
}

# ==================== EXECUTION ====================
# Everything past here is the execution of the script
# ===================================================


# Run initial scan
echo -e "${GREEN}Commencing initial scan... ${RC}"
#nmap -sU -sS -sV -O -pU:1-1000,T:- --open -oA nmap_scan -iL scope

# Run shodan host query against each element in scope.
#while IFS= read -r line; do
#	shodan host $line -O shodanoutput
#done < scope

# Parse generated Shodan File
#shodan parse --fields ip_str,port --separator , shodanoutput.json.gz > shodanHosts.csv

# Parse Output into scope files for utils. 
echo -e "${GREEN}Parsing scan results... ${RC}"
nmapparse

cd scanparse/

# Generate Host Discovery Appendix File
cut -d ',' -f 1,2 parsed_nmap.csv | sort | uniq -u | cat ../shodanHosts.csv - | awk -F, '{a[$1] = a[$1] ? a[$1] FS $2 : $2} END {for (i in a) print i "," a[i]}' > appendix.csv

# sslscan against all ssl targets
echo -e "${GREEN}Testing SSL... ${RC}"
#sslscan --xml=sslresults.xml --targets=ssl.txt

# ssh-audit against all ssh targets
echo -e "${GREEN}Testing SSH... ${RC}"
#ssh-audit --targets=ssh.txt -v 

# query dehashed if a domain name was given
if [ $# -gt 0 ] ;then
	searchTerm=$1
	dehashQuery
fi

