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

#include "cosa_webconfig_api.h"
#include "meshagent.h"
#include "meshsync_msgs.h"
#include "cosa_meshagent_internal.h"
 

const char meshService[] = "meshwifi";
extern MeshSync_MsgItem meshSyncMsgArr[];
extern COSA_DATAMODEL_MESHAGENT* g_pMeshAgent;
//extern MeshStatus_item meshWifiStatusArr[];


bool mesh_set_enabled(bool enable)
{
    // MeshInfo("Entering into %s\n",__FUNCTION__);
    unsigned char bit_mask = 0;

    if(enable)
        bit_mask = bit_mask | 0x02;

    // If the enable value is different or this is during setup - make it happen.
    if (Mesh_GetEnabled(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr) != enable)
    {
        meshSetSyscfg(enable, true);
        handleMeshEnable((void *)bit_mask);
    }

    return getMeshErrorCode();
}

int validate_mesh_enable( bool  mesh_enable , bool eth_backhaul_enable )
{
    char rdk_dcs[2][128];
    char vendor_dcs[2][128];
    int i=0;
    int ret = MB_OK;

    strncpy(rdk_dcs[0], "Device.WiFi.Radio.1.X_RDKCENTRAL-COM_DCSEnable", 128);
    strncpy(rdk_dcs[1], "Device.WiFi.Radio.2.X_RDKCENTRAL-COM_DCSEnable", 128);
    strncpy(vendor_dcs[0], "Device.WiFi.Radio.1.X_COMCAST-COM_DCSEnable", 128);
    strncpy(vendor_dcs[1], "Device.WiFi.Radio.2.X_COMCAST-COM_DCSEnable", 128);
    
    if(mesh_enable)
    {
        if(is_bridge_mode_enabled())
        {
            MeshError("MESH_ERROR:Fail to enable Mesh when Bridge mode is on\n");
            ret = MB_ERROR_BRIDGE_MODE_ENABLED;
        }
        if(is_radio_enabled(rdk_dcs[0],rdk_dcs[1])) {
            for(i=0; i<2; i++) {
                if(rdk_dcs[i][0]!=0 && set_wifi_boolean_enable(rdk_dcs[i], "false")==FALSE) {
                    MeshError("MESH_ERROR:Fail to enable Mesh because fail to turn off %s\n", rdk_dcs[i]);
                    ret = MB_ERROR_RADIO_OFF;
                }
            }
        }
        if(is_radio_enabled(vendor_dcs[0],vendor_dcs[1])) {
            for(i=0; i<2; i++) {
                if(vendor_dcs[i][0]!=0 && set_wifi_boolean_enable(vendor_dcs[i], "false")==FALSE) {
                    MeshError("MESH_ERROR:Fail to enable Mesh because fail to turn off %s\n", vendor_dcs[i]);
                    ret = MB_ERROR_RADIO_OFF;
                }
            }
        }
    }
    else {
        MeshInfo("Mesh disabled, Disable Ethernet bhaul if enabled\n");
        if( eth_backhaul_enable )
        {
            MeshInfo("Send Eth Bhaul disable notification to plume\n");
            Mesh_SendEthernetMac("00:00:00:00:00:00");
        }
    }

    return ret;
}

/* API to get the subdoc version */

uint32_t getBlobVersion(char* subdoc)
{

    char subdoc_ver[64] = {0}, buf[72] = {0};
    snprintf(buf,sizeof(buf),"%s_version",subdoc);
    if ( syscfg_get( NULL, buf, subdoc_ver, sizeof(subdoc_ver)) == 0 )
    {
        int version = atoi(subdoc_ver);
        return (uint32_t)version;
    }
    return 0;
}

/* API to update the subdoc version */
int setBlobVersion(char* subdoc,uint32_t version)
{

    char subdoc_ver[64] = {0}, buf[72] = {0};
    snprintf(subdoc_ver,sizeof(subdoc_ver),"%u",version);
    snprintf(buf,sizeof(buf),"%s_version",subdoc);
    if(syscfg_set(NULL,buf,subdoc_ver) != 0)
    {
        MeshError("syscfg_set failed\n");
        return -1;
    }
    else
    {
        if (syscfg_commit() != 0)
        {
            MeshError("syscfg_commit failed\n");
            return -1;
        }
    }
    return 0;
}

/* API to register all the supported subdocs , versionGet and versionSet are callback functions to get and set the subdoc versions in db */

void webConfigFrameworkInit()
{
    char *sub_docs[SUBDOC_COUNT+1]= {"mesh",(char *) 0 };
    int i;

    blobRegInfo *blobData;
    blobData = (blobRegInfo*) malloc(SUBDOC_COUNT * sizeof(blobRegInfo));
    memset(blobData, 0, SUBDOC_COUNT * sizeof(blobRegInfo));
    blobRegInfo *blobDataPointer = blobData;
    for (i=0 ; i < SUBDOC_COUNT ; i++ )
    {
        strncpy( blobDataPointer->subdoc_name, sub_docs[i], sizeof(blobDataPointer->subdoc_name)-1);
        blobDataPointer++;
    }
    blobDataPointer = blobData ;
    getVersion versionGet = getBlobVersion;
    setVersion versionSet = setBlobVersion;
    register_sub_docs(blobData,SUBDOC_COUNT,versionGet,versionSet);
}

/* API to clear the buffer */
void clear_mb_cache(t_cache *tmp_mb_cache)
{
    tmp_mb_cache->mesh_enable = false;
    tmp_mb_cache->ethernetbackhaul_enable = false;
}

/* API to print cache */
void print_mb_cache(t_cache *tmp_mb_cache)
{
    MeshInfo("mb->mesh_enable is %s\n", (1 == tmp_mb_cache->mesh_enable)?"true":"false");
    MeshInfo("mb->ethernetbackhaul_enable is %s\n", (1 == tmp_mb_cache->ethernetbackhaul_enable)?"true":"false");

}

/* API to back up the cache */
void backup_mb_cache(t_cache *tmp_mb_cache,t_cache *tmp_mb_cache_bkup)
{
    tmp_mb_cache_bkup->mesh_enable = tmp_mb_cache->mesh_enable;
    tmp_mb_cache_bkup->ethernetbackhaul_enable = tmp_mb_cache->ethernetbackhaul_enable;
}

/* API to apply mesh  requests to DB */
int apply_mb_cache_ToDB(t_cache *cache)
{
    int ret = MB_OK;
    
    ret = mesh_set_enabled(cache->mesh_enable);
    if (ret == MB_OK)
    {
        Mesh_SetMeshEthBhaul(cache->ethernetbackhaul_enable, false, true);
    }

    return ret;
}

/* Read blob entries into a cache */
int set_meshbackhaul_conf(meshbackhauldoc_t *mb,t_cache *cache)
{
    int count = 0;
    int ret = MB_OK;
 
    ret = validate_mesh_enable (mb->mesh_enable, mb->ethernetbackhaul_enable );
    if ( ret == MB_OK )
    {
        cache->mesh_enable = mb->mesh_enable;
        cache->ethernetbackhaul_enable = mb->ethernetbackhaul_enable;
    }
    return ret;
}

/* Initialize cache , this API will be called once in boot up */
void init_mb_cache(t_cache *tmp_mb_cache)
{
    PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;

    tmp_mb_cache->mesh_enable = pMyObject->meshEnable;
    tmp_mb_cache->ethernetbackhaul_enable = pMyObject->PodEthernetBackhaulEnable;
}

/* CallBack API to execute Mesh Blob request */
pErr Process_MB_WebConfigRequest(void *Data)
{
    int ret;
    pErr execRetVal = NULL;

    execRetVal = (pErr) malloc (sizeof(Err));
    if (execRetVal == NULL )
    {
        MeshError("%s : malloc failed\n",__FUNCTION__);
        return execRetVal;
    }

    memset(execRetVal,0,sizeof(Err));
    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    meshbackhauldoc_t *mb = (meshbackhauldoc_t *) Data ;
    MeshInfo("Mesh configurartion recieved\n");
    backup_mb_cache(&mb_cache,&mb_cache_bkup);

    ret  = set_meshbackhaul_conf(mb,&mb_cache);
    if ( MB_OK != ret )
    {
        if ( MB_ERROR_BRIDGE_MODE_ENABLED == ret )
        {
            MeshInfo("%s : Mesh Enabled Failed: Bridge mode Enabled\n",__FUNCTION__);
            execRetVal->ErrorCode = MB_ERROR_BRIDGE_MODE_ENABLED;

            strncpy(execRetVal->ErrorMsg,"Mesh Enable Failed: Bridge mode Enabled",sizeof(execRetVal->ErrorMsg)-1);
        }
        else if ( MB_ERROR_RADIO_OFF == ret )
        {
            MeshInfo("%s : Mesh Enabled Failed: Radio is off\n",__FUNCTION__);
            execRetVal->ErrorCode = MB_ERROR_RADIO_OFF;
            strncpy(execRetVal->ErrorMsg,"Mesh Enable Failed: Radio is off",sizeof(execRetVal->ErrorMsg)-1);
        }
        backup_mb_cache(&mb_cache_bkup,&mb_cache);
        return execRetVal;
    }
    ret = apply_mb_cache_ToDB(&mb_cache);
    if ( MB_OK != ret ) 
    {
        if ( MB_ERROR_BANDSTEERING_ENABLED == ret )
        {
            MeshInfo("%s : Mesh Enabled Failed: Bandsteering Enabled\n",__FUNCTION__);
            execRetVal->ErrorCode = MB_ERROR_BANDSTEERING_ENABLED;

            strncpy(execRetVal->ErrorMsg,"Mesh Enable Failed: Bandsteerin Enabled",sizeof(execRetVal->ErrorMsg)-1);
        }
        else if ( MB_ERROR_MESH_SERVICE_START_FAIL == ret )
        {
            MeshInfo("%s : Mesh Enabled Failed: Mesh service start failed\n",__FUNCTION__);
            execRetVal->ErrorCode = MB_ERROR_MESH_SERVICE_START_FAIL;
            strncpy(execRetVal->ErrorMsg,"Mesh Enable Failed: Mesh service start failed",sizeof(execRetVal->ErrorMsg)-1);
        }
        else if (MB_ERROR_MESH_SERVICE_STOP_FAIL == ret )
        {
            MeshInfo("%s : Mesh Enabled Failed: Mesh service stop failed\n",__FUNCTION__);
            execRetVal->ErrorCode = MB_ERROR_MESH_SERVICE_STOP_FAIL;
            strncpy(execRetVal->ErrorMsg,"Mesh Enable Failed: Mesh service stop failed",sizeof(execRetVal->ErrorMsg)-1);
        }
        else if (MB_ERROR_PRECONDITION_FAILED == ret )
        {
            MeshInfo("%s : Mesh Enabled Failed: Precondition failed\n",__FUNCTION__);
            execRetVal->ErrorCode = MB_ERROR_PRECONDITION_FAILED;
            strncpy(execRetVal->ErrorMsg,"Mesh Enable Failed: Mesh precondition failed",sizeof(execRetVal->ErrorMsg)-1);
        }
        backup_mb_cache(&mb_cache_bkup,&mb_cache);
        return execRetVal;
    }

    MeshInfo("Mesh configuration applied\n");
    MeshInfo("mb->mesh_enable is %s\n", (1 == mb->mesh_enable)?"true":"false");
    MeshInfo("mb->ethernetbackhaul_enable is %s\n", (1 == mb->ethernetbackhaul_enable)?"true":"false");
    snprintf(execRetVal->ErrorMsg,sizeof(execRetVal->ErrorMsg) - 1, "%s", (mb->mesh_enable?"enabled":"disabled"));

    return execRetVal;

}

bool is_cash_matches_db (const char * param)
{
    bool ret = true;
    int value;
    char buffer[10]={0};

    syscfg_get( NULL, param, buffer, sizeof(buffer));
    value = (0 == strcmp (buffer, "true"))?1:0;
    if ( value != mb_cache_bkup.mesh_enable ) 
    {
        ret = false;
    }

    return ret;
}

/* Callback function to rollback when mesh  blob execution fails */
int rollback_MeshBackhaul()
{
    // return 0 to notify framework when rollback is success
    MeshInfo(" Entering %s \n",__FUNCTION__);

    int ret = 0;
    int value;
    char buf[10]={0};

    if (!is_cash_matches_db ("mesh_enable"))
    {
        apply_mb_cache_ToDB(&mb_cache_bkup);
        backup_mb_cache(&mb_cache_bkup,&mb_cache);
    }

    return ret ;
}

void freeResources_MeshBackhaul(void *arg)
{
    MeshInfo(" Entering %s \n",__FUNCTION__);
    execData *blob_exec_data  = (execData*) arg;

    meshbackhauldoc_t *rpm = (meshbackhauldoc_t *) blob_exec_data->user_data;

    if ( rpm != NULL )
    {
        meshbackhauldoc_destroy( rpm );
    }

    if ( blob_exec_data != NULL )
    {
        free(blob_exec_data);
        blob_exec_data = NULL ;
    }
}
