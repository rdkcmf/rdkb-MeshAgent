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

#include "ansc_platform.h"
#include "ansc_load_library.h"
#include "cosa_plugin_api.h"
#include "plugin_main.h"

#include "cosa_meshagent_dml.h"
#include "cosa_meshagent_internal.h"
#include "meshagent.h"

#define THIS_PLUGIN_VERSION                         1

COSA_DATAMODEL_MESHAGENT* g_pMeshAgent = NULL;

int ANSC_EXPORT_API
COSA_Init
    (
        ULONG                       uMaxVersionSupported, 
        void*                       hCosaPlugInfo         /* PCOSA_PLUGIN_INFO passed in by the caller */
    )
{
	
    PCOSA_PLUGIN_INFO               pPlugInfo  = (PCOSA_PLUGIN_INFO)hCosaPlugInfo;

    if ( uMaxVersionSupported < THIS_PLUGIN_VERSION )
    {
    	MeshError("%s Exit ERROR Version not supported! \n", __FUNCTION__);

      /* this version is not supported */
        return -1;
    }   
    
    pPlugInfo->uPluginVersion       = THIS_PLUGIN_VERSION;
    /* register the back-end apis for the data model */
    MeshInfo("Registering the back-end apis for the data model\n");


    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "MeshAgent_GetParamBoolValue",    MeshAgent_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "OVS_GetParamBoolValue",          OVS_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "MeshAgent_SetParamBoolValue",    MeshAgent_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "OVS_SetParamBoolValue",          OVS_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "MeshAgent_GetParamStringValue",  MeshAgent_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "MeshAgent_SetParamStringValue",  MeshAgent_SetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "MeshAgent_GetParamUlongValue",   MeshAgent_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "MeshAgent_Validate",             MeshAgent_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "MeshAgent_Commit",               MeshAgent_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "MeshAgent_Rollback",  MeshAgent_Rollback);
    

    /* Create MeshAgent Object for Settings */
    g_pMeshAgent = (PCOSA_DATAMODEL_MESHAGENT)CosaMeshAgentCreate();

    if ( g_pMeshAgent )
    {
    	  MeshInfo("Initializing CosaMeshAgent\n");
    	  CosaMeshAgentInitialize(g_pMeshAgent);
          MeshInfo(("  Initializing WebConfig Framework!\n"));
          webConfigFrameworkInit();
          MeshInfo(("  Initializing WebConfig Framework done!\n"));
    }
    else
    {
    	MeshError("%s exit ERROR CosaMeshAgentCreate returned 0!!!\n", __FUNCTION__);
    }

	

    return  0;
}

BOOL ANSC_EXPORT_API
COSA_IsObjectSupported
    (
        char*                        pObjName
    )
{
    
    return TRUE;
}

void ANSC_EXPORT_API
COSA_Unload
    (
        void
    )
{
    /* unload the memory here */
    if ( g_pMeshAgent )
    {
        
        CosaMeshAgentRemove(g_pMeshAgent);
    }

    g_pMeshAgent = NULL;
}
