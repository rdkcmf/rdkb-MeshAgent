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
#include "safec_lib_common.h"
#include <msgpack.h>
#include "helpers.h"
#include "cosa_apis_util.h"
#include "base64.h"

#define DEBUG_INI_NAME  "/etc/debug.ini"
extern bool isXB3Platform;

extern COSA_DATAMODEL_MESHAGENT* g_pMeshAgent;

/**
 * @brief LOGInit Initialize RDK Logger
 */
void Mesh_EBCleanup();

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
    *  GreAcc_GetParamBoolValue
    *  GreAcc_SetParamBoolValue
    *  OVS_GetParamBoolValue
    *  OVS_SetParamBoolValue
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
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t        rc = -1;
    int            ind = -1;
    /* check the parameter name and return the corresponding value */
    rc = strcmp_s("Enable",strlen("Enable"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
        *pBool = g_pMeshAgent->meshEnable;
        return TRUE;
    }
    rc = strcmp_s("PodEthernetBackhaulEnable",strlen("PodEthernetBackhaulEnable"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
        MeshInfo("Pod ethernet bhaul mode get\n");
        *pBool = g_pMeshAgent->PodEthernetBackhaulEnable;
        return TRUE; 
    }
    rc = strcmp_s("Opensync",strlen("Opensync"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
	MeshInfo("Opensync Enable get\n");
	*pBool = g_pMeshAgent->OpensyncEnable;
	return TRUE;
    }
        MeshWarning(("Unsupported parameter '%s'\n"), ParamName);
    return FALSE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        GreAcc_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value for RFC GRE Acceleration;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
GreAcc_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pMeshAgent->GreAccEnable;
        return TRUE;
    }
    else
     MeshWarning("Unsupported parameter '%s'\n", ParamName);
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        OVS_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value for RFC Openvswitch;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
OVS_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;
    /* check the parameter name and return the corresponding value */
    rc = strcmp_s("Enable",strlen("Enable"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
        *pBool = g_pMeshAgent->OvsEnable;
        return TRUE;
    }
    else
     MeshWarning("Unsupported parameter '%s'\n", ParamName);
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
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;
    /* check the parameter name and return the corresponding value */
        rc = strcmp_s("URL",strlen("URL"),ParamName,&ind);
        ERR_CHK(rc);
        if( (ind == 0) && (rc == EOK))
	{
            rc = strcpy_s(pValue, *pUlSize, g_pMeshAgent->meshUrl);
            if(rc != EOK)
	    {
	        ERR_CHK(rc);
		return -1;
	    }
	    return 0;
	}
	
    rc = strcmp_s("X_RDKCENTRAL-COM_Connected-Client",strlen("X_RDKCENTRAL-COM_Connected-Client"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
       // trap the value but don't return anything.
       return 0;
    }
    rc = strcmp_s("Data",strlen("Data"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
       MeshInfo(("Data Get Not supported\n"));
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
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;
    rc = strcmp_s("Status",strlen("Status"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
        *puLong = g_pMeshAgent->meshStatus;
        return TRUE;
    }

    rc = strcmp_s("State",strlen("State"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
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
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    char rdk_dcs[2][128];
    char vendor_dcs[2][128];
    int i=0;
    errno_t rc = -1;
    int ind = -1;

	rc = strcpy_s(rdk_dcs[0],sizeof(rdk_dcs[0]),"Device.WiFi.Radio.1.X_RDKCENTRAL-COM_DCSEnable");
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return FALSE;
    }
	rc = strcpy_s(rdk_dcs[1],sizeof(rdk_dcs[1]),"Device.WiFi.Radio.2.X_RDKCENTRAL-COM_DCSEnable");
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return FALSE;
    }
	rc = strcpy_s(vendor_dcs[0],sizeof(vendor_dcs[0]),"Device.WiFi.Radio.1.X_COMCAST-COM_DCSEnable");
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return FALSE;
    }
	rc = strcpy_s(vendor_dcs[1],sizeof(vendor_dcs[1]),"Device.WiFi.Radio.2.X_COMCAST-COM_DCSEnable");
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return FALSE;
    }
	
    rc = strcmp_s("Enable",strlen("Enable"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
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
                        MeshError("MESH_ERROR:Fail to enable Mesh because fail to turn off %s\n", rdk_dcs[i]);
                        return FALSE;
                   }
                 }
              }
              if(is_radio_enabled(vendor_dcs[0],vendor_dcs[1])) {
                 for(i=0; i<2; i++) {
                   if(vendor_dcs[i][0]!=0 && set_wifi_boolean_enable(vendor_dcs[i], "false")==FALSE) {
                        MeshError("MESH_ERROR:Fail to enable Mesh because fail to turn off %s\n", vendor_dcs[i]);
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
                Mesh_EBCleanup();
                Mesh_SendEthernetMac("00:00:00:00:00:00");
                //Mesh_SetMeshEthBhaul(false,true); 
              } 
         }

        Mesh_SetEnabled(bValue, false, true);
        return TRUE;
    }
    rc = strcmp_s("PodEthernetBackhaulEnable",strlen("PodEthernetBackhaulEnable"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
        MeshInfo("Pod ethernet bhaul mode set\n");
        Mesh_SetMeshEthBhaul(bValue,false,true);
        return TRUE; 
    }    
    rc = strcmp_s("Opensync",strlen("Opensync"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
        MeshInfo("Opensync set\n");
        Opensync_Set(bValue,false,true);
	return TRUE;
    }
    MeshWarning(("Unsupported parameter '%s'\n"), ParamName);
    return FALSE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        GreAcc_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value for GRE Acceleration;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
GreAcc_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;

    if (isXB3Platform) {
        rc = strcmp_s("Enable",strlen("Enable"), ParamName,&ind);
        ERR_CHK(rc);
        if( (ind == 0) && (rc == EOK))
        {
            MeshInfo("Gre Acc mode set\n");
            return Mesh_SetGreAcc(bValue,false, true);
        }
        else
            MeshWarning("Unsupported parameter '%s'\n", ParamName);
        return FALSE;
    }
    MeshWarning("GRE Acc Unsupported '%s'\n", ParamName);
    return FALSE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        OVS_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value for OpenVSwitch;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
OVS_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;
    
    rc = strcmp_s("Enable",strlen("Enable"), ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
     MeshInfo("OVS mode set with commit\n");
     return Mesh_SetOVS(bValue,false,true);
    }
    else
     MeshWarning("Unsupported parameter '%s'\n", ParamName);
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
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;
    /* check the parameter name and return the corresponding value */
    rc = strcmp_s("State", strlen("State"), ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))    
    {
        // Make sure the value is valid
        if ((long)puLong >= MESH_STATE_FULL && puLong < MESH_STATE_TOTAL) {
            Mesh_SetMeshState(puLong, false, true);
            return TRUE;
        }
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);
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
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    errno_t rc = -1;
    int ind = -1;

    rc = strcmp_s("URL",strlen("URL"), ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK)) 
    {
        Mesh_SetUrl(pString, false);
        return TRUE;
    }

    rc = strcmp_s("X_RDKCENTRAL-COM_Connected-Client", strlen("X_RDKCENTRAL-COM_Connected-Client"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK)) 
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
                        rc = strncpy_s(pIface, sizeof(pIface), param, sizeof(pIface)-1);
                        if(rc != EOK)
			{
			   ERR_CHK(rc);
			   return FALSE;
			}
        	    	break;
        	    case 2: // Mac Address
                        rc = strncpy_s(pMac, sizeof(pMac), param, sizeof(pMac)-1);
                        if(rc != EOK)
                        {
                           ERR_CHK(rc);
                           return FALSE;
                        }
        	    	break;
        	    case 3: // Status
                        rc = strncpy_s(pStatus, sizeof(pStatus), param, sizeof(pStatus)-1);
                        if(rc != EOK)
                        {
                           ERR_CHK(rc);
                           return FALSE;
                        }
        	    	break;
        	    case 4: // Hostname
                        rc = strncpy_s(pHost, sizeof(pHost), param, sizeof(pHost)-1);
                        if(rc != EOK)
                        {
                           ERR_CHK(rc);
                           return FALSE;
                        }
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
    rc = strcmp_s("Data", strlen("Data"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
        char * decodeMsg =NULL;
        int decodeMsgSize =0;
        int size =0;

        msgpack_zone mempool;
        msgpack_object deserialized;
        msgpack_unpack_return unpack_ret;
        decodeMsgSize = b64_get_decoded_buffer_size(strlen(pString));
        decodeMsg = (char *) malloc(sizeof(char) * decodeMsgSize);
        size = b64_decode( pString, strlen(pString), decodeMsg );
        MeshInfo("base64 decoded data contains %d bytes\n",size);

        msgpack_zone_init(&mempool, 2048);
        unpack_ret = msgpack_unpack(decodeMsg, size, NULL, &mempool, &deserialized);

        switch(unpack_ret)
        {
            case MSGPACK_UNPACK_SUCCESS:
                MeshInfo("MSGPACK_UNPACK_SUCCESS :%d\n",unpack_ret);
                break;
            case MSGPACK_UNPACK_EXTRA_BYTES:
                MeshInfo("MSGPACK_UNPACK_EXTRA_BYTES :%d\n",unpack_ret);
                break;
            case MSGPACK_UNPACK_CONTINUE:
                MeshInfo("MSGPACK_UNPACK_CONTINUE :%d\n",unpack_ret);
                break;
            case MSGPACK_UNPACK_PARSE_ERROR:
                MeshInfo("MSGPACK_UNPACK_PARSE_ERROR :%d\n",unpack_ret);
                break;
            case MSGPACK_UNPACK_NOMEM_ERROR:
                MeshInfo("MSGPACK_UNPACK_NOMEM_ERROR :%d\n",unpack_ret);
                break;
            default:
                MeshInfo("Message Pack decode failed with error: %d\n", unpack_ret);
        }

        msgpack_zone_destroy(&mempool);
        MeshInfo("End message pack decode\n");
        //End of msgpack decoding

        if(unpack_ret == MSGPACK_UNPACK_SUCCESS)
        {
            meshbackhauldoc_t *mb;
            mb = meshbackhauldoc_convert( decodeMsg, size+1 );

            if ( decodeMsg )
            {
                free(decodeMsg);
                decodeMsg = NULL;
            }

            if (NULL != mb)
            {
                MeshInfo("mb->mesh_enable is %s\n", (1 == mb->mesh_enable)?"true":"false");
                MeshInfo("mb->ethernetbackhaul_enable is %s\n", (1 == mb->ethernetbackhaul_enable)?"true":"false");
                MeshInfo("mb->subdoc_name is %s\n", mb->subdoc_name);
                MeshInfo("mb->version is %lu\n", (unsigned long)mb->version);
                MeshInfo("mb->transaction_id is %d\n", mb->transaction_id);
                MeshInfo("Mesh configuration received\n");

                execData *execDataMb = NULL ;

                execDataMb = (execData*) malloc (sizeof(execData));

                if ( execDataMb != NULL )
                {
                    memset(execDataMb, 0, sizeof(execData));

                    execDataMb->txid = mb->transaction_id;
                    execDataMb->version = mb->version;

                    strncpy(execDataMb->subdoc_name,"mesh",sizeof(execDataMb->subdoc_name)-1);
                    execDataMb->user_data = (void*) mb ;
                    execDataMb->calcTimeout = NULL ;
                    execDataMb->executeBlobRequest = Process_MB_WebConfigRequest;
                    execDataMb->rollbackFunc = rollback_MeshBackhaul ;
                    execDataMb->freeResources = freeResources_MeshBackhaul ;

                    PushBlobRequest(execDataMb);

                    MeshInfo("PushBlobRequest complete\n");

                    return TRUE;

                }
                else
                {
                    MeshInfo("execData memory allocation failed\n");
                    meshbackhauldoc_destroy( mb );

                    return FALSE;

                }
            }
            return TRUE;

        }
        else
        {
            if ( decodeMsg )
            {
                free(decodeMsg);
                decodeMsg = NULL;
            }
            MeshInfo("Corrupted Mesh value\n");
            return FALSE;
        }
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
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;

    if(!strlen(pMyObject->meshUrl))
    {  
    	/* Coverity Issue Fix - CID:125155 : Printf Args */
        MeshInfo("%s: Url String is Empty \n", __FUNCTION__);
        rc = strcpy_s(pReturnParamName, *puLength, "Url is empty");
        if(rc != EOK)
	{
	    ERR_CHK(rc);
	}
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
    UNREFERENCED_PARAMETER(hInsContext);
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
    UNREFERENCED_PARAMETER(hInsContext);
    PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;

    // reset url
    Mesh_GetUrl((char *)pMyObject->meshUrl, sizeof(pMyObject->meshUrl));
    pMyObject->meshState = Mesh_GetMeshState();
    pMyObject->meshEnable = Mesh_GetEnabled(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr);

    return 0;
}


