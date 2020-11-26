/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <stdio.h>
#include "ansc_platform.h"
#include "meshagent.h"
#include "telemetry_busmessage_sender.h"

int main(int argc, char* argv[])
{   
    UNREFERENCED_PARAMETER(argv);
    UNREFERENCED_PARAMETER(argc);
    /* Initialize logger*/
    
    LOGInit();
    
    MeshInfo("Registering MeshAgent component '%s' with CR ..\n", MESHAGENT_COMPONENT_NAME);

    t2_init("mesh-agent");
    
    msgBusInit(MESHAGENT_COMPONENT_NAME);
       
    MeshInfo("Registered MeshAgent component '%s' with CR ..\n", MESHAGENT_COMPONENT_NAME);

    while(1)
    {
        sleep(30);
    }

    MeshInfo("MeshAgent %s EXIT\n", __FUNCTION__ );

    return 0;
}

