#!/usr/bin/env python2
import os
import re
from tempfile import NamedTemporaryFile
import shutil
import sys

tempFile = NamedTemporaryFile(delete=False)
#debug = sys.argv[1]

#def myDebug(message):
#  if debug == "debug":
#      print message

runningConfig=os.popen('iptables-save').read()
runningConfig = runningConfig.split("\n")
# reset counters to zero
tempRun = []
for line in runningConfig:
    tempRun.append(re.sub(r'\[\d+:\d+\]','[0:0]', line))
runningConfig = tempRun
#print(runningConfig)

staticFile = '/etc/sysconfig/iptables'
with open(staticFile, 'r') as staticConfig:
    staticConfig = staticConfig.read().split("\n")
    #print(staticConfig)


runningChainsCount=0
runningChainsList=[]
runningChainsIdx=0
for i in runningConfig:
    if re.match(r'^\*|^COMMIT$', i):
        myKey = {}
        myKey[str(i)] = runningChainsIdx
        runningChainsList.append(myKey)
        runningChainsCount =  runningChainsCount + 1
        #print runningChainsCount
    runningChainsIdx = runningChainsIdx + 1
#print "runningChainsList = %s" % runningChainsList

staticChainsCount=0
staticChainsList=[]
staticChainsIdx=0
for i in staticConfig:
    if re.match(r'^\*|^COMMIT$', i):
        myKey = {}
        myKey[str(i)] = staticChainsIdx
        staticChainsList.append(myKey)
        staticChainsCount = staticChainsCount + 1
#        print i
#        print staticChainsCount
    staticChainsIdx = staticChainsIdx + 1
#print "staticChainsList = %s" % staticChainsList


runningTables = {}
rtIdx = 0
## Lets create our chain sections w_out chainName or COMMIT
for table in runningChainsList[0::2]:
 #   print "rtIDX = %s" % rtIdx
    tableName = table.keys()[0]
#    print "tableName = %s" % tableName
#    print "RCL = %s" % runningChainsList
    startIdx = runningChainsList[rtIdx][tableName] + 1
    endIdx = runningChainsList[rtIdx+1]['COMMIT']
    runningTables[tableName] = []
    runningTables[tableName].append(runningConfig[startIdx:endIdx])
    # Bump count
    rtIdx = rtIdx + 2
#print "runningTables = %s" % runningTables
#print ""
#print ""

staticTables = {}
stIdx = 0
## Lets create our chain sections w_out chainName or COMMIT
for table in staticChainsList[0::2]:
#    print "stIDX = %s" % stIdx
    tableName = table.keys()[0]
#    print "tableName = %s" % tableName
#    print "SCL = %s" % staticChainsList
    startIdx = staticChainsList[stIdx][tableName] + 1
    endIdx = staticChainsList[stIdx+1]['COMMIT']
    staticTables[tableName] = []
    staticTables[tableName].append(staticConfig[startIdx:endIdx])
    # Bump count
    stIdx = stIdx + 2
#print "staticTables = %s" % staticTables
#print ""
#print ""

unmanagedChains = ('DOCKER','CATTLE','br-','--dport 5000 -j MASQUERADE')

mangledRunning = {}
# Add the running chains to dict as a priority
for key in runningTables:
    if key not in mangledRunning: # create it
        mangledRunning[key] = []
    for myList in runningTables[key]:
        for line in myList:
          if line.startswith(":"):
              mangledRunning[key].append(line)

#print "mangledRunning1 = %s" % mangledRunning
#print ""
#print ""

# Now add any other chains that dont exist
for key in staticTables:
    if key not in mangledRunning:
        mangledRunning[key] = []
    for myList in staticTables[key]:
        if line.startswith(":") and line not in mangledRunning[key]:
              mangledRunning[key].append(line)
            
#print "mangledRunning2 = %s" % mangledRunning
#print ""
#print ""

## Now add the running 'unmanagedChains'-rules in first, followed by our static rules
for key in runningTables:
    for myList in runningTables[key]:
       for line in myList:
           # If you see a rule that exists in unmanagedChains
           if any(word.upper() in line.upper() for word in unmanagedChains) and not line.startswith(":"):
              # Add it in first
              mangledRunning[key].append(line)
#print "mangledRunning3 = %s" % mangledRunning              

## Add our desired rules after
for key in staticTables:
    for myList in staticTables[key]:
        for line in myList:
            if not any(word.upper() in line.upper() for word in unmanagedChains) and not line.startswith(":"):
                mangledRunning[key].append(line)


#print "mangledRunning4 = %s" % mangledRunning
#print "" * 2

## Output the rules
#for key in mangledRunning:
#    print key
#    for table in mangledRunning[key]:
#        print table
#    print 'COMMIT'

with open(tempFile.name, 'w') as file:
    for key in mangledRunning:
        file.write("%s\n" % key)
        for table in mangledRunning[key]:
            file.write("%s\n" % table)
        file.write("COMMIT\n")

shutil.move(tempFile.name, '/tmp/output.ipt')

# Perform the import into iptables
os.system("iptables-restore /tmp/output.ipt")
os.system("rm -f /tmp/output.ipt")
