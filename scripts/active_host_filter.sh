#!/bin/bash
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

#Predeclare our data arrays
mac_array=()
iface_array=()
host_array=()
active_array=()

display_usage() { 
    echo -e "Usage: active_host_filter.sh <file> \n"
} 

if [ "$#" -ne 1 ]; then
    display_usage
    exit 1
fi
count=-1
# If file exists 
if [[ -f "$1" ]]
then
    # open the file and start looking for our key data
    while read line           
    do
        case "$line" in
        *PhysAddress*)
            let count++
            read line
            array=( $line )
            mac_array[$count]=`echo ${array[4]} | sed 's/^[ \t]*//'`
            ;;
        *.Layer1Interface*)
            read line
            array=( $line )
            iface=`echo ${array[4]} | sed 's/^[ \t]*//'`
            iface_array[$count]="Other"
            case "$iface" in
                *Ethernet*)
                    iface_array[$count]="Ethernet"
                    ;;
                *MoCA*)
                    iface_array[$count]="MoCA"
                    ;;
                *WiFi*)
                    iface_array[$count]="WiFi"
                    ;;
            esac
            ;;
        *HostName*)
            read line
            array=( $line )
            host_array[$count]=`echo ${array[4]} | sed 's/^[ \t]*//'`
            ;;
        *.Active*)
            read line
            array=( $line )
            active_array[$count]=`echo ${array[4]} | sed 's/^[ \t]*//'`
            ;;
        esac
    done <$1
else
    echo -e "File " $1 " does not exist\n"
    exit 1
fi

# Now if everything went according to plan, we can walk the arrays and output our connected clients list
for (( c=0; c<=$count; c++ ))
do
    if [ ${active_array[$c]} == 'true' ]
    then
        echo ${mac_array[$c]}'|'${iface_array[$c]}'|'${host_array[$c]}
    fi
done

exit 0
