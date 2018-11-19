#!/usr/bin/python
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2018 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

# We'll take the input from a dmcli command and then parse that to return a
# list of active devices
#
# dmcli command: dmcli eRT getv Device.Hosts.Host.
#
# We are looking for the following returned fields in the list:
# PhysAddress - Mac address of the connected device
# Layer1Interface - Interface device is connected to
# HostName - Host name for connected device
# Active - whether or not this device is currently active.
import sys

class Client:
    def __init__(self, mac):
        self.mac = mac

    def addIface(self, iface):
        self.iface = iface
        
    def addActive(self, active):
        self.active = active
        
    def addHostName(self, host):
        self.host = host    
    
clientArr = []

if len(sys.argv) > 1:  # user has given a file to parse
    input = open(sys.argv[1])
else:
    input = sys.stdin   # otherwise read from stdin
    
line = input.readline()

while line:
    if 'PhysAddress' in line:
        # the PhysAddress is the 1st item in the data model
        # When we see this, we will create a new element in our client list   
        line = input.readline()
        val = line.split()
        if len(val) == 5:
            clientArr.append(Client(val[4]))
    elif 'Layer1Interface' in line:
        line = input.readline()
        val = line.split()
        if len(val) == 5:
            # Add this to the last entry in our array
            if 'Ethernet' in val[4]:
                clientArr[-1].addIface('Ethernet')
            elif 'WiFi' in val[4]:
                clientArr[-1].addIface('WiFi')
            elif 'MoCA' in val[4]:
                clientArr[-1].addIface('MoCA')
            else:
                clientArr[-1].addIface('Other')
        else:
            clientArr[-1].addIface("None")
    elif 'HostName' in line:
        line = input.readline()
        val = line.split()
        if len(val) == 5:
            clientArr[-1].addHostName(val[4])
        else:
            clientArr[-1].addHostName("")
    elif '.Active' in line:
        line = input.readline()
        val = line.split()
        if len(val) == 5:
            clientArr[-1].addActive(val[4])
    # go on to the next line.
    line = input.readline()

if input is not sys.stdin:
    input.close()

# now that we've processed through the dmcli command, we'll print out our results
for obj in clientArr:
    if obj.active == 'true':
        print obj.mac + '|' + obj.iface + '|' + obj.host
