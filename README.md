usage: scantool.sh <targetfile> <projectname> <mode>
Note: only enter IP adresses or (sub)domains (without http://) in your <targetfile>

Mode:
use +mode to include a specific scan
use -mode to exclude a specific scan

Possible values of scanmodes:
all: do every scan available
fast: use faster (excluding slow) settings for scans
superfast: use fastest (but less complete) settings for scans
ping: ping
traceroute: traceroute
dns: DNS stuff
nmap: do nmap TCP portscan
nmapUDP: do nmap UDP portscan [nyi]
Note: scanmodes below rely on nmap results:
nikto: HTTP server scan
arachni: HTTP server scan [nyi]
ssl: SSL scan
ssh: SSH scan

