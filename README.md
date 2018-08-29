# PaloAltoFirewallChecker
Check if traffic has been allowed by the specific paloalto firewall 

## Usage
<pre>
python paloaltofirewallchecker.py "10.225.243.119" "10.225.240.12" "TCP/22" "ssh"

Output:
Test traffic src: 10.225.243.119, dst: 10.225.240.12, service: TCP/22, application: ssh
Found Security Rule: n-Bastion to Internet
</pre>

