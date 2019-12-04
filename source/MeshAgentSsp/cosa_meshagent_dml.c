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

#include "cosa_meshagent_dml.h"

#include "ansc_platform.h"
#include "cosa_meshagent_internal.h"
#include "meshagent.h"
#include "ssp_global.h"
#include "syslog.h"
#include "ccsp_trace.h"


#define DEBUG_INI_NAME  "/etc/debug.ini"

extern COSA_DATAMODEL_MESHAGENT* g_pMeshAgent;

/**
 * @brief LOGInit Initialize RDK Logger
 */

void LOGInit()
{
#ifdef FEATURE_SUPPORT_RDKLOG
     rdk_logger_init(DEBUG_INI_NAME);
#endif
}

/**
 * @brief _MESHAGENT_LOG MESHAGENT RDK Logger API
 *
 * @param[in] level LOG Level
 * @param[in] msg Message to be logged 
 */
void _MESHAGENT_LOG(unsigned int level, const char *msg, ...)
{
	va_list arg;
	char *pTempChar = NULL;
	int ret = 0;
	unsigned int rdkLogLevel = LOG_DEBUG;

	switch(level)
	{
		case MESHAGENT_LOG_ERROR:
			rdkLogLevel = RDK_LOG_ERROR;
			break;

		case MESHAGENT_LOG_INFO:
			rdkLogLevel = RDK_LOG_INFO;
			break;

		case MESHAGENT_LOG_WARNING:
			rdkLogLevel = RDK_LOG_WARN;
			break;

        case MESHAGENT_LOG_DEBUG:
            rdkLogLevel = RDK_LOG_DEBUG;
            break;
	}
	
	
	if( rdkLogLevel <= RDK_LOG_INFO )
	{
		pTempChar = (char *)malloc(4096);
		if(pTempChar)
		{
			
			va_start(arg, msg);
			ret = vsnprintf(pTempChar, 4096, msg,arg);
			if(ret < 0)
			{
				perror(pTempChar);
			}
			va_end(arg);
			 
			RDK_LOG(rdkLogLevel, "LOG.RDK.MESH", "%s", pTempChar);
			
			if(pTempChar !=NULL)
			{
				free(pTempChar);
				pTempChar = NULL;
			}
			
		}
	}
	
}


/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_Mesh.

    *  MeshAgent_GetParamBoolValue
    *  MeshAgent_GetParamStringValue
    *  MeshAgent_GetParamUlongValue
    *  MeshAgent_SetParamBoolValue
    *  MeshAgent_SetParamStringValue
    *  MeshAgent_Validate
    *  MeshAgent_Commit
    *  MeshAgent_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        MeshAgent_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshAgent_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pMeshAgent->meshEnable;
        return TRUE;
    }
    else if( AnscEqualString(ParamName, "PodEthernetBackhaulEnable", TRUE))
    {
     MeshInfo("Pod ethernet bhaul mode get\n");
     *pBool = g_pMeshAgent->PodEthernetBackhaulEnable;
     return TRUE; 
    }
    else
     MeshWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        MeshAgent_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
MeshAgent_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;
	
	if( AnscEqualString(ParamName, "URL", TRUE))
	{
	    AnscCopyString(pValue, g_pMeshAgent->meshUrl);
	    return 0;
	}
	
    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_Connected-Client", TRUE))
    {
       // trap the value but don't return anything.
       return 0;
    }

	MeshError("Unsupported Namespace:%s\n", ParamName);
	return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        MeshAgent_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshAgent_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    if( AnscEqualString(ParamName, "Status", TRUE))
    {
        *puLong = g_pMeshAgent->meshStatus;
        return TRUE;
    }

    if( AnscEqualString(ParamName, "State", TRUE))
    {
        *puLong = g_pMeshAgent->meshState;
        return TRUE;
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);
    return FALSE;
}


extern BOOL is_radio_enabled(char *dcs1, char *dcs2);
extern BOOL is_bridge_mode_enabled();
extern BOOL set_wifi_boolean_enable(char *parameterName, char *parameterValue);
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MeshAgent_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshAgent_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{

    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;
    char rdk_dcs[2][128];
    char vendor_dcs[2][128];
    int i=0;

    strncpy(rdk_dcs[0], "Device.WiFi.Radio.1.X_RDKCENTRAL-COM_DCSEnable", 128);
    strncpy(rdk_dcs[1], "Device.WiFi.Radio.2.X_RDKCENTRAL-COM_DCSEnable", 128);
    strncpy(vendor_dcs[0], "Device.WiFi.Radio.1.X_COMCAST-COM_DCSEnable", 128);
    strncpy(vendor_dcs[1], "Device.WiFi.Radio.2.X_COMCAST-COM_DCSEnable", 128);

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
	 if( TRUE == bValue )
         {
              if(is_bridge_mode_enabled())
              {
                   MeshError(("MESH_ERROR:Fail to enable Mesh when Bridge mode is on\n"));
                   return FALSE;
              }
              if(is_radio_enabled(rdk_dcs[0],rdk_dcs[1])) {
                 for(i=0; i<2; i++) {
                   if(rdk_dcs[i][0]!=0 && set_wifi_boolean_enable(rdk_dcs[i], "false")==FALSE) {
                        MeshError(("MESH_ERROR:Fail to enable Mesh because fail to turn off %s\n", rdk_dcs[i]));
                        return FALSE;
                   }
                 }
              }
              if(is_radio_enabled(vendor_dcs[0],vendor_dcs[1])) {
                 for(i=0; i<2; i++) {
                   if(vendor_dcs[i][0]!=0 && set_wifi_boolean_enable(vendor_dcs[i], "false")==FALSE) {
                        MeshError(("MESH_ERROR:Fail to enable Mesh because fail to turn off %s\n", vendor_dcs[i]));
                        return FALSE;
                   }
                 }
              }
         }
         else {
              MeshInfo("Mesh disabled, Disable Ethernet bhaul if enabled\n");
              if( g_pMeshAgent->PodEthernetBackhaulEnable)
              {
                MeshInfo("Send Eth Bhaul disable notification to plume\n");
                Mesh_SetMeshEthBhaul(false,true); 
              } 
         }

        Mesh_SetEnabled(bValue, false);
        return TRUE;
    }
    else if( AnscEqualString(ParamName, "PodEthernetBackhaulEnable", TRUE))
    {
     MeshInfo("Pod ethernet bhaul mode set\n");
     Mesh_SetMeshEthBhaul(bValue,false);
     return TRUE; 
    }
    else
     MeshWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MeshAgent_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       puLong
            );

    description:

        This function is called to set Ulong parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       puLong
                The updated ULong value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshAgent_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       puLong
    )
{

    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;
    if( AnscEqualString(ParamName, "State", TRUE))
    {
        // Make sure the value is valid
        if (puLong >= MESH_STATE_FULL && puLong < MESH_STATE_TOTAL) {
            Mesh_SetMeshState(puLong, false, true);
            return TRUE;
        }
    }

    MeshWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MeshAgent_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                 int                         pString
            );

    description:

       This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
// Currently, SET is not supported for Name parameter

BOOL
MeshAgent_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;

    if( AnscEqualString(ParamName, "URL", TRUE))
    {
        Mesh_SetUrl(pString, false);
        return TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDKCENTRAL-COM_Connected-Client", TRUE))
    {
#ifdef USE_NOTIFY_COMPONENT
        char pIface[12] = {0}; // can be "Ethernet", "WiFi", "MoCA", "Other"
        char pMac[MAX_MAC_ADDR_LEN] = {0};
        char pStatus[12] = {0}; // can be "Online", "Offline"
        char pHost[256] = {0}; // hostname
        char *param;
        char delim[2] = ",";
        int count = 0;

        param = strtok(pString, delim);

        while (param != NULL)
        {
        	    switch (count)
        	    {
        	    case 0: // Connected-Client tag
        	    	break;
        	    case 1: // Interface
        	    	    strncpy (pIface, param, sizeof(pIface)-1);
        	    	break;
        	    case 2: // Mac Address
     	        strncpy (pMac, param, sizeof(pMac)-1);
        	    	break;
        	    case 3: // Status
        	    		strncpy (pStatus, param, sizeof(pStatus)-1);
        	    	break;
        	    case 4: // Hostname
        	    		strncpy (pHost, param, sizeof(pHost)-1);
        	    	break;
        	    default:
        	    	break;
        	    }
        		count ++;
        		param = strtok(NULL, delim);
        }

        MeshInfo("Connected-Client Notification : MAC = %s, Iface = %s, Host = %s, Status = %s \n", pMac, pIface, pHost, pStatus);

        Mesh_UpdateConnectedDevice(pMac, pIface, pHost, pStatus);
#endif
        return TRUE;
    }

    MeshError("Unsupported Namespace:%s\n", ParamName);
    return FALSE;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        MeshAgent_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
MeshAgent_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;

    if(!strlen(pMyObject->meshUrl))
    {
        MeshInfo("Url String is Empty \n", __FUNCTION__);
        AnscCopyString(pReturnParamName, "Url is empty");
        return FALSE;
    }

    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        MeshAgent_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
MeshAgent_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        MeshAgent_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation error found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
MeshAgent_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;

    // reset url
    Mesh_GetUrl((char *)pMyObject->meshUrl, sizeof(pMyObject->meshUrl));
    pMyObject->meshState = Mesh_GetMeshState();
    pMyObject->meshEnable = Mesh_GetEnabled(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr);

    return 0;
}


