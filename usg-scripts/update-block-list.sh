#!/bin/vbash
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin
while read p; do
	/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall group address-group testgroup1 address $p
done <IPList.txt
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end
