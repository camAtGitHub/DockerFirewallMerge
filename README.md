# Docker Firewall Merge aka DFWM
## Problem
Modifying firewall rules on a host that runs Docker or Rancher (cattle) causes the docker-bridges and rancher NAT rules to be blown away, causing all your containers networking to break.

## Solution
Modify /etc/sysconfig/iptables as normal and instead of running `iptables-restore /etc/sysconfig/iptables`  run as root:  `dockerFirewallMerge.py`

## What it does
It dumps your (working) running IPTables rules, scans for your docker and cattle rules and attempts to put them back into your ruleset first.

## Assumptions
Plenty were made.  `unmanagedChains` ie. DOCKER / CATTLE do not exist in your normal sysconfig/iptables ruleset. 

## Changelog
0.1 - First release. Very hacky. Lots of assumptions made about the environment. 

## TODO
- Debugging output
- Dry runs / Show changes
- Debian compatibility ?
- Less hacks regarding `--dport 5000 -j MASQUERADE`

## Other
Please contribute! 
