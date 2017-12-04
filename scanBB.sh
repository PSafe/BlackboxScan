#!/bin/bash

#####################################
#			CONTRIBUTORS			#
# Ken Cijsouw						#
# Jeffrey Bouter					#
# Erik Douwes						#
# Jan Kadijk						#
# Erik Alberts						#
#####################################

# CopyLeft: All rights reversed
# GPLv3
# Last updated: 9 december 2014
# Version 0.6

# To-Do:
# Make start-question for custom DNS server (when running dnsenum)
# Supply specific port(s) as input param to be targeted only


# Set notification variables:
not_status="[$(tput setaf 2)Status$(tput sgr0)]  :"
not_input="[$(tput setaf 4)Input$(tput sgr0)]   :"
not_warning="[$(tput setaf 3)Warning$(tput sgr0)] :"
not_error="[$(tput setaf 1)Error$(tput sgr0)]   :"

fade_in=">----"
fade_out="----<"

# supported scanmodes
do_all=0;
do_fast=0;
do_superfast=0;
do_ping=0;
do_trace=0;
do_dns=0;
do_nmap=0;
do_nikto=0;
do_arachni=0;
do_ssl=0;
do_ssh=0;

# Usage
if [ "$1" = "--help" ]
then
	echo "usage: scantool.sh <targetfile> <projectname> <mode>"
	echo "Note: only enter IP adresses or (sub)domains (without http://) in your <targetfile>"
	echo ""
	echo "Mode:"
	echo "use +mode to include a specific scan"
	echo "use -mode to exclude a specific scan"
	echo ""
	echo "Possible values of scanmodes:"
	echo "all: do every scan available"
	echo "fast: use faster (excluding slow) settings for scans"
# fast scan not defined yet
	echo "superfast: use fastest (but less complete) settings for scans"
# superfast scan excludes all fast scan excludes, plus nmap vuln scans, and only portscans the top 1000 ports
	echo "ping: ping"
	echo "traceroute: traceroute"
	echo "dns: DNS stuff"
	echo "nmap: do nmap TCP portscan"
	echo "nmapUDP: do nmap UDP portscan [nyi]"
	echo "Note: scanmodes below rely on nmap results:"
	echo "nikto: HTTP server scan"
	echo "arachni: HTTP server scan [nyi]"
	echo "ssl: SSL scan"
	echo "ssh: SSH scan"

	exit 0
fi

if [ $(id -u) -gt 0 ]; then
	echo "$not_error You are NOT root, neccesary for some scans; exiting."
	exit 1
fi

# All three arguments must be present
if [ "$1" = "" ] || [ "$2" = "" ] || [ "$3" = "" ]
then
	echo "$not_error All three arguments must be present ( <targetfile> <project> [[+|-]<mode>]* ); exiting."
	echo "$not_warning See --help for options and usage"
	exit 0
fi

# Init
target=$1
project=$2
curr_path="$PWD"
ports_http="ports_http.txt"
ports_ssl="ports_ssl.txt"
ports_ssh="ports_ssh.txt"

# TODO: add paths as variables

# get scanmodes right, include and exlude given modes

shift 2; # get to third argument
while (( "$#" )); do
#	echo "Processing parameter: $1";
	if [[ "$(echo $1 | cut -c1)" == "+" ]]; then
#		Include
		mode=$(echo $1 | cut -d'+' -f 2)
		case $mode in
			all)
				do_all=1;;
			fast)
				do_fast=1;;
			superfast)
				do_superfast=1;;
			ping)
				do_ping=1;;
			trace)
				do_trace=1;;
			dns)
				do_dns=1;;
			nmap)
				do_nmap=1;;
			nikto)
				do_nikto=1;;
			ssl)
				do_ssl=1;;
			ssh)
				do_ssh=1;;
			arachni)
				do_arachni=1;;
			*)
				echo "Unknown scanmode to include: $mode; exiting."
				exit 0
		esac
	else
		if [[ "$(echo $1 | cut -c1)" == "-" ]]; then
#		Exclude
			mode=$(echo $1 | cut -d'-' -f 2)
			case $mode in
				all)
					do_all=-1;;
				fast)
					do_fast=-1;;
				superfast)
					do_superfast=-1;;
				ping)
					do_ping=-1;;
				trace)	
					do_trace=-1;;
				dns)
					do_dns=-1;;
				nmap)
					do_nmap=-1;; #possibly overriden! TODO: warn for this behaviour
				nikto)
					do_nikto=-1;;
				ssl)
					do_ssl=-1;;
				ssh)
					do_ssh=-1;;
				arachni)
					do_arachni=-1;;
				*)
					echo "Unknown scanmode to exclude: $mode; exiting."
					exit 0
			esac
		else
			echo "Invalid action for scanmode";
		fi
	fi
# proceed to next argument
shift

done
#echo "Determined scans to do:"
#if [[ "$do_all" == "1" ]]; then 
#	echo "Full scan" 
#fi
#if [[ "$do_nikto" == "1" ]]; then 
#	echo "Nikto scan" 
#fi
#echo "but not doing:"
#if [[ "$do_all" == "0" ]]; then 
#	echo "Full scan" 
#fi
#if [[ "$do_nikto" == "0" ]]; then 
#	echo "Nikto scan" 
#fi

##################################
# PREPARATION with possible EXIT #
##################################

# Create project directory if it does not exist
if [ -d "$project" ]
then
	echo "$not_warning Project $project already exists. Are you sure you want to continue? [Y/n]"
	read duplicate_answer
	if [ "$duplicate_answer" = "n" ]; then
		echo "Exiting.."
		exit 0
	fi
else
	mkdir $project
fi

# Create folders for all given targets
echo "$not_status Creating output folders"
for ip in `cat $target`
do
	if [ -d $ip ]; then
		echo "$not_warning Output folder $ip already present. Will overwrite existing data. Continue? [Y/n]"
		read duplicate_answer
		if [ "$duplicate_answer" = "n" ]; then
			echo "Exiting.. "
			exit 0
		fi
	else
		echo "$not_status Creating folder $project/$ip"
		mkdir $project/$ip
	fi
done

################
# FOOTPRINTING #
################

# IP-adress Intern
echo "$not_status Getting IP-Adress Intern for $(hostname)"
echo "Using command: ifconfig " > $project/ifconfig_intern_IP.txt
ifconfig >> $project/ifconfig_intern_IP.txt

# IP-adres Extern
echo "$not_status Get IP-adress Extern for $(hostname)"
echo "Using command: curl v4.ident.me" > $project/ifconfig_extern_IP.txt
curl -m3 v4.ident.me >> $project/ifconfig_extern_IP.txt
echo "" >>$project/ifconfig_extern_IP.txt


#################
# Functions     #
#################

# ping
ping_scan() {
	echo "$not_status $fade_in"
	echo "$not_status PINGing: $ip 5 times"
	echo "Using command: ping -c5 $ip" > $project/$ip/ping.txt
	ping -c5 $ip >> $project/$ip/ping.txt
	echo "$not_status Done PINGing"
	echo "$not_status $fade_out"
}

# trace route
traceroute_scan() {
	echo "$not_status $fade_in"
	echo "$not_status TRACErouting: $ip"
	echo "Using command: traceroute -T $ip" > $project/$ip/traceroute.txt
	traceroute -T $ip >> $project/$ip/traceroute.txt
	echo "$not_status Done performing TRACEroute"
	echo "$not_status $fade_out"		
}

# DNS Enum
dnsenum_scan(){
	echo "$not_status $fade_in"
	echo "$not_status Launching DNSenum scan on $1"
	echo "Using command: dnsenum --nocolor $1" > $project/$ip/dnsenum.txt
	dnsenum --nocolor $1 >> $project/$ip/dnsenum.txt
	echo "$not_status Done performing DNSenum scan"	
	echo "$not_status $fade_out"		
}

# Whois
whois_scan() {
	# whois on domain
	echo "$not_status $fade_in"
	echo "$not_status Launching WHOIS on $1"
	echo "Using command: whois $1 " > $project/$ip/whois.txt
	whois $1 >> $project/$ip/whois.txt
	echo "$not_status Done performing WHOIS scan"
	echo "$not_status $fade_out"

	# Fierce DNS
	echo "$not_status $fade_in"
	echo "$not_status Launching FIERCE on $1"
	echo "Using command: fierce.pl $1 " > $project/$ip/fierce.txt
	cd /opt/fierce/
	fierce -dns $1 >> $curr_path/$project/$ip/fierce.txt
	cd -
	echo "$not_status Done performing FIERCE scan"
	echo "$not_status $fade_out"
}

# Dns
dns_scan() {
	echo "$not_status $fade_in"	
	echo "$not_status Launching the DNS scan.."
	# Test if the target is an actual IP address
	if [[ $(echo $ip | cut -d'.' -f1) != *[!0-9]* ]]; then
		if [ $(echo $ip | cut -d'.' -f1) -eq 192 ] || [ $(echo $ip | cut -d'.' -f1) -eq 172 ] || [ $(echo $ip | cut -d'.' -f1) -eq 10 ]; then
			echo "$not_warning $ip seems like a local ip address. Skipping..."
		else
			echo "$not_status dig reverse lookup: $ip"
			echo "Using command: dig +noall +answer -x $ip +trace" > $project/$ip/dig.txt
			dig +noall +answer -x $ip +trace >> $project/$ip/dig.txt
		fi
	else
		echo "$not_warning $ip doesn't seem to be an ip address"
		echo "$not_status $ip seems to be a URL, running dnsenum on it..."
		dnsenum_scan $ip
		echo "$not_status $ip seems to be a URL, will do whois on domain..."
		whois_scan `echo $ip | awk -F. '{print $2"."$3}'`

		echo "$not_status DIGing host $ip..."
		echo "Using command: dig +noall +answer $ip" > $project/$ip/dig.txt
		dig +noall +answer $ip >> $project/$ip/dig.txt
		echo "Please run reverse lookup manualy..."
#		echo "Trying reverse IP lookup..."
#		echo "Using command: dig +noall +answer -x $(cat $project/$ip/dig.txt | cut -f6)"
#		dig +noall +answer -x $(cat $project/$ip/dig.txt | cut -f6) >> $project/$ip/dig.txt
	fi
	echo "$not_status Done performing DNS scan"	
	echo "$not_status $fade_out"	
}


# nmap scan
nmap_scan() {
	echo "$not_status $fade_in"
	# NMap port scan
	# TODO: script=default,safe scan hangs at 99%. Why?

	# set port range and scan scripts depending on 'fast' scan option
#	scripts="--script=\"vuln and not broadcast-*\" "
	ports="-p-"
	if [[ "$do_superfast" == "1"  ]]; then
		ports=""; #default top 1000 ports
#		scripts=""; #no scripts
	fi

	scanoption="-sS -A -T4 $ports -Pn -vvv"

	# ugly, settings scripts variable doesnt work somehow
	if [[ "$do_superfast" == "1"  ]]; then
		echo "$not_status NMAPping TCP ports: $ip using $scanoption"
		nmap -oA "$project/$ip/nmap" $scanoption $ip
	else
		echo "$not_status NMAPping TCP ports: $ip using $scanoption --script=\"vuln and not broadcast-*\""
		nmap -oA "$project/$ip/nmap" $scanoption --script="vuln and not broadcast-*" $ip
	fi		

	# Dump specific open ports into files for use in specialized functions
	cat "$project/$ip/nmap.nmap" | grep "open " | grep "http" | cut -d'/' -f1 > "$project/$ip/$ports_http"
	cat "$project/$ip/nmap.nmap" | grep "open " | grep "ssl/" | cut -d'/' -f1 > "$project/$ip/$ports_ssl"
	cat "$project/$ip/nmap.nmap" | grep "open " | grep "ssh/" | cut -d'/' -f1 > "$project/$ip/$ports_ssh"
	# TODO add webdav detection and kickoff davtest

	echo "$not_status Done performing NMAP scan"
	echo "$not_status $fade_out"		
}

# nikto scan
nikto_scan() {
	echo "$not_status $fade_in"	
	echo "$not_status Doing a NIKTO scan"
	if [ $(cat "$project/$ip/$ports_http" | wc -l) -gt "8" ]; then
		echo "$not_warning Nikto found too many open HTTP ports to scan. Risk of more applications on one server is too high. Please run nikto manually"
		echo "$not_warning Storing open ports in $project/$ip/$ports_http: see this file for a list of all ports."
	else
		if [ $(cat "$project/$ip/$ports_http" | wc -l) -eq "0" ]; then
			echo "$not_status Nikto has nothing to do"
			echo "No http ports found." > "$project/$ip/nikto.txt"
		else
			for port in $(cat "$project/$ip/$ports_http")
			do
				echo "$not_status nikto testing: $ip:$port"
				echo "Using command: nikto -host $ip -port $port" >> "$project/$ip/nikto_$port.txt"
				cd /opt/nikto/program/
				nikto -host "$ip" -port "$port" -Save . -Display P >> "$curr_path/$project/$ip/nikto_$port.txt"
				cd -
				echo "" >> "$project/$ip/nikto_$port.txt"
				echo "=========" >> "$project/$ip/nikto_$port.txt"
				echo "" >> "$project/$ip/nikto_$port.txt"
				# TODO Add kickoff of webdav-test ('WebDAV enabled')
			done
		fi
	fi
	echo "$not_status Done performing NIKTO scan"
	echo "$not_status $fade_out"	
}

# sslscan
ssl_scan() {
	echo "$not_status $fade_in"
	echo "$not_status Doing an SSL scan using testssl.sh"
	if [ $(cat "$project/$ip/$ports_ssl" | wc -l) -eq "0" ]; then
		echo "$not_status sslscan has nothing to do"
		echo "No SSL ports found." > "$project/$ip/sslscan.txt"
	else
		for port in $(cat "$project/$ip/$ports_ssl")
		do
			echo "$not_status SSL Scanning: $ip:$port"
			echo "Using command: testssl --openssl /opt/openssl-dirty/bin/openssl.Linux.x86_64 $ip:$port" > "$project/$ip/testssl_$port.txt"
			testssl --openssl /opt/openssl-dirty/bin/openssl.Linux.x86_64 $ip:$port >> "$project/$ip/testssl_$port.txt"
		done
	fi
	echo "$not_status Done performing SSL scan"	
	echo "$not_status $fade_out"
}

# sshscan
ssh_scan() {
	echo "$not_status $fade_in"
	echo "$not_status Doing an SSH-audit scan using ssh-audit.sh"
	if [ $(cat "$project/$ip/$ports_ssh" | wc -l) -eq "0" ]; then
		echo "$not_status ssh-audit scan has nothing to do"
		echo "No SSH ports found." > "$project/$ip/ssh-audit.txt"
	else
		for port in $(cat "$project/$ip/$ports_ssh")
		do
			echo "$not_status SSH Scanning: $ip:$port"
			echo "Using command: ssh-audit -v -n --level=info $ip:$port" > "$project/$ip/ssh-audit_$port.txt"
			ssh-audit -v -n --level=info $ip:$port >> "$project/$ip/ssh-audit_$port.txt"
		done
	fi
	echo "$not_status Done performing SSH-audit scan"	
	echo "$not_status $fade_out"	
}

#########################################
# Main loop; calls defined functions    #
#########################################


# execute scans
for ip in `cat $target`
do
	echo "$not_status Processing target: $ip"

# ping
	if [[ ("$do_all" == "1" || "$do_ping" == "1") && "$do_ping" != "-1" ]]; then 
		ping_scan
	fi

# traceroute
	if [[ ("$do_all" == "1" || "$do_trace" == "1") && "$do_trace" != "-1" ]]; then 
		traceroute_scan
	fi

#DNS (dig, dnsenum, fierce)
	if [[ ("$do_all" == "1" || "$do_dns" == "1") && "$do_dns" != "-1" ]]; then 
		dns_scan
	fi

# full blown TCP portscan also conditional of other dependant scanmodes
	if [[ "$do_all" == "1" || "$do_nmap" == "1" || "$do_ssl" == "1" || "$do_ssh" == "1" || "$do_nikto" == "1" ]]; then 
		if [[ "$do_nmap" != "1" && "$do_all" != "1" ]]; then
			echo "WARNING: nmap scan was not requested, but is necessary for dependant requested scans. Will perform Nmap TCP portscan."
		fi
		nmap_scan
	fi

# UDP portscan

# SSL scan testssl.sh
	if [[ ("$do_all" == "1" || "$do_ssl" == "1") && "$do_ssl" != "-1" ]]; then 
		ssl_scan
	fi

# SSH scan ssh-audit
	if [[ ("$do_all" == "1" || "$do_ssh" == "1") && "$do_ssh" != "-1" ]]; then 
		ssh_scan
	fi

# Nikto
	if [[ ("$do_all" == "1" || "$do_nikto" == "1") && "$do_nikto" != "-1" ]]; then 
		nikto_scan
	fi

# Arachni? Eerst tunen tot bruikbare proporties

#end
	echo "$not_status Done with $ip."
	echo ""

done

