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

#ifndef _RDKB_MESH_AGENT_C_
#define _RDKB_MESH_AGENT_C_

/*
 * @file cosa_mesh_apis.c
 * @brief Mesh Agent
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <stdarg.h>
#include "stdbool.h"
#include <pthread.h>
#include <syscfg/syscfg.h>
#include <sysevent/sysevent.h>

#include <fcntl.h>

#include "ansc_platform.h"
#include "meshsync_msgs.h"
//#include "ccsp_trace.h"
#include "cosa_apis_util.h"
#include "cosa_meshagent_internal.h"
#include "meshagent.h"
#include "mesh_client_table.h"
#include "ssp_global.h"
#include "cosa_webconfig_api.h"
#include "safec_lib_common.h"

// TELEMETRY 2.0 //RDKB-26019
#include <telemetry_busmessage_sender.h>

/**************************************************************************/
/*      LOCAL VARIABLES:                                                  */
/**************************************************************************/
#if defined(ENABLE_MESH_SOCKETS)
/*
 * Unix Domain Sockets
 */
#include <sys/socket.h>
#include <sys/un.h>

#define MAX_CONNECTED_CLIENTS 10  // maximum number of connected clients
const char meshSocketPath[] = MESH_SOCKET_PATH_NAME;
static int clientSockets[MAX_CONNECTED_CLIENTS] = {0};
static int clientSocketsMask = 0; //Prash
static int meshError = MB_OK;
#else
/*
 * Message Queues
 */
#include <mqueue.h>

static mqd_t qd_server; // msg queue server handle
const int QUEUE_PERMISSIONS=0660;
const int MAX_MESSAGES=10;  // max number of messages the can be in the queue
#endif

#define MESH_ENABLED "/nvram/mesh_enabled"   
#define LOCAL_HOST   "127.0.0.1"
#define POD_LINK_SCRIPT "/usr/ccsp/wifi/mesh_status.sh"
#define POD_IP_PREFIX   "192.168.245."
#define XF3_PLATFORM "XF3"
#define RADIO_ENABLE_24  "Device.WiFi.Radio.1.Enable"
#define RADIO_ENABLE_50  "Device.WiFi.Radio.2.Enable"
#define RADIO_STATUS_24  "Device.WiFi.Radio.1.Status"
#define RADIO_STATUS_50  "Device.WiFi.Radio.2.Status"
#define STATE_DOWN "Down"
#define STATE_FALSE "false"

static bool isPaceXF3 = false;
#define ETHBHAUL_SWITCH "/usr/sbin/deviceinfo.sh"

static bool s_SysEventHandler_ready = false;
extern  ANSC_HANDLE             bus_handle;

static pthread_t mq_server_tid; // server thread id
static pthread_t lease_server_tid; // dnsmasq lease thread id
int sysevent_fd;
int sysevent_fd_gs;
token_t sysevent_token_gs;
token_t sysevent_token;
static pthread_t sysevent_tid;


const char urlOld[] = "NOC-URL-DEV";
const char urlDefault[] = "NOC-URL-PROD";
const char meshServiceName[] = "meshwifi";
const char meshDevFile[] = "/nvram/mesh-dev.flag";
pthread_mutex_t mesh_handler_mutex = PTHREAD_MUTEX_INITIALIZER;
#define _DEBUG 1
#define THREAD_NAME_LEN 16 //length is restricted to 16 characters, including the terminating null byte

//Prash 
static int dnsmasqFd;
static struct sockaddr_in dnsserverAddr;

extern COSA_DATAMODEL_MESHAGENT* g_pMeshAgent;

// Mesh Status structure
typedef struct
{
    eMeshWifiStatusType    mStatus;
    char                  *mStr;
} MeshStatus_item;

MeshStatus_item meshWifiStatusArr[] = {
    {MESH_WIFI_STATUS_OFF,     "Off"},
    {MESH_WIFI_STATUS_INIT,    "Init"},
    {MESH_WIFI_STATUS_MONITOR, "Monitor"},
    {MESH_WIFI_STATUS_FULL,    "Full"}
};

// Mesh State structure
typedef struct
{
    eMeshStateType      mState;
    char                *mStr;
} MeshState_item;

MeshState_item meshStateArr[] = {
    {MESH_STATE_FULL,      "Full"},
    {MESH_STATE_MONITOR,   "Monitor"},
    {MESH_STATE_WIFI_RESET,"Reset"}
};

// This Array should have MESH_SYNC_MSG_TOTAL-1 entries
MeshSync_MsgItem meshSyncMsgArr[] = {
    {MESH_WIFI_RESET,                       "MESH_WIFI_RESET",                      "wifi_init"},
    {MESH_WIFI_RADIO_CHANNEL,               "MESH_WIFI_RADIO_CHANNEL",              "wifi_RadioChannel"},
    {MESH_WIFI_RADIO_CHANNEL_MODE,          "MESH_WIFI_RADIO_CHANNEL_MODE",         "wifi_RadioChannelMode"},
    {MESH_WIFI_SSID_NAME,                   "MESH_WIFI_SSID_NAME",                  "wifi_SSIDName"},
    {MESH_WIFI_SSID_ADVERTISE,              "MESH_WIFI_SSID_ADVERTISE",             "wifi_SSIDAdvertisementEnable"},
    {MESH_WIFI_AP_SECURITY,                 "MESH_WIFI_AP_SECURITY",                "wifi_ApSecurity"},
    {MESH_WIFI_AP_KICK_ASSOC_DEVICE,        "MESH_WIFI_AP_KICK_ASSOC_DEVICE",       "wifi_kickApAssociatedDevice"},
    {MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES,   "MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES",  "wifi_kickAllApAssociatedDevice"},
    {MESH_WIFI_AP_ADD_ACL_DEVICE,           "MESH_WIFI_AP_ADD_ACL_DEVICE",          "wifi_addApAclDevice"},
    {MESH_WIFI_AP_DEL_ACL_DEVICE,           "MESH_WIFI_AP_DEL_ACL_DEVICE",          "wifi_delApAclDevice"},
    {MESH_WIFI_MAC_ADDR_CONTROL_MODE,       "MESH_WIFI_MAC_ADDR_CONTROL_MODE",      "wifi_MacAddressControlMode"},
    {MESH_SUBNET_CHANGE,                    "MESH_SUBNET_CHANGE",                   "subnet_change"},
    {MESH_URL_CHANGE,                       "MESH_URL_CHANGE",                      "mesh_url"},
    {MESH_WIFI_STATUS,                      "MESH_WIFI_STATUS",                     "mesh_status"},
    {MESH_WIFI_ENABLE,                      "MESH_WIFI_ENABLE",                     "mesh_enable"},
    {MESH_STATE_CHANGE,                     "MESH_STATE_CHANGE",                    "mesh_state"},
    {MESH_WIFI_TXRATE,                      "MESH_WIFI_TXRATE",                     "wifi_TxRate"},
    {MESH_CLIENT_CONNECT,                   "MESH_CLIENT_CONNECT",                  "client_connect"},
    {MESH_DHCP_RESYNC_LEASES,               "MESH_DHCP_RESYNC_LEASES",              "lease_resync"},
    {MESH_DHCP_ADD_LEASE,                   "MESH_DHCP_ADD_LEASE",                  "lease_add"},
    {MESH_DHCP_REMOVE_LEASE,                "MESH_DHCP_REMOVE_LEASE",               "lease_remove"},
    {MESH_DHCP_UPDATE_LEASE,                "MESH_DHCP_UPDATE_LEASE",               "lease_update"},
    {MESH_WIFI_RADIO_CHANNEL_BW,            "MESH_WIFI_RADIO_CHANNEL_BW",           "channel_update"},
    {MESH_ETHERNET_MAC_LIST,                "MESH_ETHERNET_MAC_LIST",               "process_eth_mac"},
    {MESH_RFC_UPDATE,                       "MESH_RFC_UPDATE",                      "eb_enable"}};
typedef struct
{
    eMeshIfaceType  mType;
    char           *mStr;
} MeshIface_item;

MeshIface_item meshIfaceArr[] = {
        {MESH_IFACE_NONE,     "None"},
        {MESH_IFACE_ETHERNET, "Ethernet"},
        {MESH_IFACE_MOCA,     "MoCA"},
        {MESH_IFACE_WIFI,     "WiFi"},
        {MESH_IFACE_OTHER,    "Other"}};


/**************************************************************************/
/*      LOCAL FUNCTIONS:                                                  */
/**************************************************************************/
static int msgQServer(void *data);
static int  msgQSend(MeshSync *data);
static void Mesh_SetDefaults(ANSC_HANDLE hThisObject);
static bool Mesh_Register_sysevent(ANSC_HANDLE hThisObject);
static void *Mesh_sysevent_handler(void *data);
int Mesh_Init(ANSC_HANDLE hThisObject);
void Mesh_InitClientList();
void changeChBandwidth( int, int);
static char EthPodMacs[MAX_POD_COUNT][MAX_MAC_ADDR_LEN];
static int eth_mac_count = 0;

int Get_MeshSyncType(char * name ,eMeshSyncType *type_ptr)
{
    errno_t rc       = -1;
    int     ind      = -1;
    int strlength;
    int i;

    if( (name == NULL) || (type_ptr == NULL) )
       return 0;

    strlength = strlen( name );

    for (i = 0; i < MESH_SYNC_MSG_TOTAL; i++) {

        rc = strcmp_s(name, strlength, meshSyncMsgArr[i].sysStr, &ind);
        ERR_CHK(rc);
        if((ind==0) && (rc == EOK))
        {
            *type_ptr =  meshSyncMsgArr[i].mType ;
            return 1;
        }
    }
    
    return 0;
}

/**
 * @brief Mesh Agent Interface lookup function
 *
 * This function will take an interface string and convert it to an enum value
 */
eMeshIfaceType Mesh_IfaceLookup(char * iface)
{
    eMeshIfaceType ret = MESH_IFACE_OTHER;
    errno_t rc       = -1;
    int     ind      = -1;
    if (iface != NULL && iface[0] != '\0')
    {
        int i;
        int strlength;
        strlength = strlen( iface );
        for (i = 0; i < MESH_IFACE_TOTAL; i++) {
            rc = strcmp_s(iface,strlength,meshIfaceArr[i].mStr,&ind);
            ERR_CHK(rc);          
            if((ind == 0) && (rc == EOK))
            {
                ret = meshIfaceArr[i].mType;
                break;
            }
        }
    }

    return ret;
}

/**
 * @brief Mesh Agent Status lookup function
 *
 * This function will take an interface string and convert it to an enum value
 */
eMeshWifiStatusType Mesh_WifiStatusLookup(char *status)
{
    eMeshWifiStatusType ret = MESH_WIFI_STATUS_OFF;
    errno_t rc       = -1;
    int     ind      = -1;

    if (status != NULL && status[0] != '\0')
    {
        int i;
        int strlength;
        strlength = strlen( status );
        for (i = 0; i < MESH_WIFI_STATUS_TOTAL; i++) {
            rc = strcmp_s(status,strlength,meshWifiStatusArr[i].mStr,&ind);
            ERR_CHK(rc);       
            if((ind == 0) && (rc == EOK))
            {
                ret = meshWifiStatusArr[i].mStatus;
                break;
            }
        }
    }

    return ret;
}

bool isValidIpAddress(char *ipAddress)
{
    struct sockaddr_in sa = {0};
    char ip[16] = {0};
    errno_t rc = -1;

    if(ipAddress == NULL)
    {
       MeshError("ipAddress is NULL\n");
       return FALSE;
    }

    rc = strncpy_s(ip, sizeof(ip), ipAddress, 13);
    if(rc != EOK)
    {
       ERR_CHK(rc);
       MeshError("Error in copying ipAddress - %s\n", ipAddress);
       return FALSE;
    }
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    return result != 0;
}

int Mesh_DnsmasqSock(void)
{
 if(!dnsmasqFd)
 {
  FILE *cmd;
  errno_t rc = -1;
  char armIP[32] = {'\0'};;
  cmd = popen("grep \"ARM_INTERFACE_IP\" /etc/device.properties | cut -d \"=\" -f2","r");
  if(cmd == NULL) {
       return 0;
   }
  fgets(armIP, sizeof(armIP), cmd);
  pclose(cmd);
  dnsmasqFd = socket(PF_INET, SOCK_DGRAM, 0);
  if( dnsmasqFd < 0)
    return 0;
  dnsserverAddr.sin_family = AF_INET;
  dnsserverAddr.sin_port = htons(47030);
  if(!isValidIpAddress(armIP)) {
   MeshInfo("Socket bind to localhost\n");
   dnsserverAddr.sin_addr.s_addr = inet_addr(LOCAL_HOST);
  } else
  {
   MeshInfo("Socket bind to ARM IP %s\n", armIP);
   dnsserverAddr.sin_addr.s_addr = inet_addr(armIP);
  }
  rc = memset_s(dnsserverAddr.sin_zero, sizeof(dnsserverAddr.sin_zero), '\0', sizeof(dnsserverAddr.sin_zero));
  ERR_CHK(rc);
  MeshInfo("Created dnsmasq socket for Eth Bhaul mac update\n");
 }
 return 1;
}

static bool Mesh_PodAddress(char *mac, bool add)
{
  int i;
  errno_t rc = -1;
  int ind = -1;
  int strlength;
  
  if (mac == NULL)
  {
        MeshError("Error - Pod mac address is NULL\n");
	return FALSE;
  }

  strlength = strlen( mac );
  for(i =0; i <= eth_mac_count; i++)
  {
   rc = strcmp_s(mac, strlength ,EthPodMacs[i] ,&ind);
   ERR_CHK(rc);       
   if((ind == 0) && (rc == EOK))
   {
    MeshInfo("Pod mac detected as connected client, ignore update\n");
    return TRUE;
   }
  }
  if( add && (eth_mac_count < MAX_POD_COUNT) ) {
   MeshInfo("Adding the Ethernet pod mac in the local copy mac: %s idx: %d\n", mac, eth_mac_count);
    rc = strcpy_s(EthPodMacs[eth_mac_count], MAX_MAC_ADDR_LEN, mac);
   if(rc != EOK)
   {
      ERR_CHK(rc);
      MeshError("Error in copying to Ethernet pod mac\n");
      return FALSE;
   }
   eth_mac_count++;
  } 
  else
  {
   MeshInfo("Send the Connect event for this client as normal client: %s\n", mac);
  }
  
  return FALSE;
}

//Prash
/**
 *  @brief MeshAgent Process Send Pod mac to dnsmasq for filtering
 *
 *  This function will send Pod mac addr
 *  to dnsmasq for the purpose of Vendor ID filtering
 *  when Pod connected via ethernet
 */
void Mesh_SendEthernetMac(char *mac)
{
  errno_t rc = -1;
 if(Mesh_DnsmasqSock())
 {
  PodMacNotify msg = {0};
  PodMacNotify *sendBuff;
 
  sendBuff = &msg;
  msg.msgType = g_pMeshAgent->PodEthernetBackhaulEnable ?  START_POD_FILTER : STOP_POD_FILTER;
  rc = strcpy_s(msg.mac, MAX_MAC_ADDR_LEN, mac);
  if(rc != EOK)
  {
      ERR_CHK(rc);
      MeshError("Error in sending the mac via socket\n");
      close(dnsmasqFd);
      dnsmasqFd=0;
      return;
  } 

  if(dnsmasqFd) { 
    /* Coverity Issue Fix - CID:113076 : Buffer Over Run */
    /* Coverity Fix CID: 110417 CHECKED_RETURN */
   if(sendto(dnsmasqFd, (const char*)sendBuff, sizeof(PodMacNotify), 0, (struct sockaddr *)&dnsserverAddr,(sizeof dnsserverAddr)) ==-1)
     MeshError("Error sending Pod mac address to dnsmasq\n");
   else
     MeshInfo("Pod mac address sent to dnsmasq MAC: %s\n", mac);
  } 
  else
     MeshError ("Error sending Pod mac address to dnsmasq, Socket not ready MAC: %s\n", mac);
  
  close(dnsmasqFd);
  dnsmasqFd=0;
 }
 else {
    MeshError("Socket failed in %s\n", __FUNCTION__);
 }

  return;
}

static void Mesh_SendPodAddresses()
{
 int i=0;
 for(i =0; i <= eth_mac_count; i++)
 {
  MeshInfo("Send pod address %s to dnsmasq %s\n", EthPodMacs[i], __FUNCTION__);
  Mesh_SendEthernetMac( EthPodMacs[i]);
 }
}

/**
 *  @brief MeshAgent Process Sync Message
 *
 *  This function will take a sync message and process it
 */
void Mesh_ProcessSyncMessage(MeshSync rxMsg)
{
    // Parse out the messages and send the sysevents
    // Check to see if this is a valid message
    if (rxMsg.msgType >= MESH_SYNC_MSG_TOTAL)
    {
        MeshError("Error unknown message type %d - skipping\n", rxMsg.msgType);
        return;
    }

    MeshInfo("%s - %s message received.\n", __FUNCTION__, meshSyncMsgArr[rxMsg.msgType].msgStr);

    switch (rxMsg.msgType) {
    case MESH_WIFI_RADIO_CHANNEL:
    {
        char cmd[256] = {0};
        sprintf(cmd, "MESH|%d|%d",
                rxMsg.data.wifiRadioChannel.index,
                rxMsg.data.wifiRadioChannel.channel);
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_RADIO_CHANNEL].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_RADIO_CHANNEL_MODE:
    {
        char cmd[256] = {0};
        /* Coverity Issue Fix - CID:124800 : Printf args*/
        sprintf(cmd, "MESH|%d|%s|%s|%s|%s",
                rxMsg.data.wifiRadioChannelMode.index,
                rxMsg.data.wifiRadioChannelMode.channelMode,
                (rxMsg.data.wifiRadioChannelMode.gOnlyFlag?"true":"false"),
                (rxMsg.data.wifiRadioChannelMode.nOnlyFlag?"true":"false"),
                (rxMsg.data.wifiRadioChannelMode.acOnlyFlag?"true":"false")
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_RADIO_CHANNEL_MODE].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_SSID_NAME:
    {
        char cmd[256] = {0};
        sprintf(cmd, "MESH|%d|%s",
                rxMsg.data.wifiSSIDName.index,
                rxMsg.data.wifiSSIDName.ssid
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_SSID_NAME].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_SSID_ADVERTISE:
    {
        char cmd[256] = {0};
        sprintf(cmd, "MESH|%d|%s",
                rxMsg.data.wifiSSIDAdvertise.index,
                (rxMsg.data.wifiSSIDAdvertise.enable?"true":"false")
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_SSID_ADVERTISE].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_AP_SECURITY:
    {
        char cmd[256] = {0};
        sprintf(cmd, "MESH|%d|%s|%s|%s",
                rxMsg.data.wifiAPSecurity.index,
                rxMsg.data.wifiAPSecurity.passphrase,
                rxMsg.data.wifiAPSecurity.secMode,
                rxMsg.data.wifiAPSecurity.encryptMode
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_AP_SECURITY].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_AP_KICK_ASSOC_DEVICE:
    {
        char cmd[256] = {0};
        sprintf(cmd, "MESH|%d|%s",
                rxMsg.data.wifiAPKickAssocDevice.index,
                rxMsg.data.wifiAPKickAssocDevice.mac
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_AP_KICK_ASSOC_DEVICE].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES:
    {
        char cmd[256] = {0};
        sprintf(cmd, "MESH|%d",
                rxMsg.data.wifiAPKickAllAssocDevices.index
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_AP_ADD_ACL_DEVICE:
    {
        char cmd[256] = {0};
        /*Coverity Fix: CID 57148 DC.STRING_BUFFER */
        snprintf(cmd,sizeof(cmd), "MESH|%d|%s",
                rxMsg.data.wifiAPAddAclDevice.index,
                rxMsg.data.wifiAPAddAclDevice.mac
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_AP_ADD_ACL_DEVICE].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_AP_DEL_ACL_DEVICE:
    {
        char cmd[256] = {0};
        sprintf(cmd, "MESH|%d|%s",
                rxMsg.data.wifiAPDelAclDevice.index,
                rxMsg.data.wifiAPDelAclDevice.mac
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_AP_DEL_ACL_DEVICE].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_MAC_ADDR_CONTROL_MODE:
    {
        char cmd[256] = {0};
        sprintf(cmd, "MESH|%d|%s|%s",
                rxMsg.data.wifiMacAddrControlMode.index,
                (rxMsg.data.wifiMacAddrControlMode.isEnabled?"true":"false"),
                (rxMsg.data.wifiMacAddrControlMode.isBlacklist?"true":"false")
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_MAC_ADDR_CONTROL_MODE].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_STATUS:
    {
        char cmd[256] = {0};

        g_pMeshAgent->meshStatus = rxMsg.data.wifiStatus.status;

        sprintf(cmd, "MESH|%s",meshWifiStatusArr[rxMsg.data.wifiStatus.status].mStr);
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_STATUS].sysStr, cmd, 0, true);

    }
    break;
    case MESH_WIFI_RADIO_CHANNEL_BW:
    {
        MeshInfo("Recieved Channel BW change notification radioId = %d channel = %d\n", 
                  rxMsg.data.wifiRadioChannelBw.index, rxMsg.data.wifiRadioChannelBw.bw); 
        changeChBandwidth(rxMsg.data.wifiRadioChannelBw.index, rxMsg.data.wifiRadioChannelBw.bw);
    }
    break;
    case MESH_ETHERNET_MAC_LIST:
    {
      char cmd[256] = {0};
      int rc = -1;
      if( g_pMeshAgent->PodEthernetBackhaulEnable)
      {
       sprintf(cmd,"%s %s", ETHBHAUL_SWITCH, "-eb_enable");
       rc = system(cmd);
       if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
       {
        MeshError("%s: Ethernet backhaul enable failed = %d\n", cmd, WEXITSTATUS(rc));
       }
       Mesh_SendEthernetMac(rxMsg.data.ethMac.mac);
      }
      else
       MeshInfo("Ethernet bhaul disabled, ignoring the Pod mac update\n");
      Mesh_PodAddress( rxMsg.data.ethMac.mac, TRUE);
    } 
    break;
    // the rest of these messages will not come from the Mesh vendor
    case MESH_SUBNET_CHANGE:
    case MESH_URL_CHANGE:
    case MESH_WIFI_ENABLE:
    case MESH_STATE_CHANGE:
    case MESH_WIFI_TXRATE:
    default:
        break;
    }
}

static void Mesh_logLinkChange()
{
 char cmd[256] = {0};
 int rc = -1;

 if (access(POD_LINK_SCRIPT, F_OK) == 0) {
      snprintf( cmd, sizeof(cmd), "%s &", POD_LINK_SCRIPT);
      rc = system(cmd);
      if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
      {
        MeshError("%s: pod link script fail rc = %d\n", cmd, WEXITSTATUS(rc));
      }
   }
}

/**
 *  @brief Mesh Agent dnsmasq lease server thread
 *  This function will create a server socket for the dnsmasq lease notifications. 
 *  dnsmasq sends the lease update related notifications to mesh-agent
 *
 *  @return 0
 */
static int leaseServer(void *data)
{
   errno_t rc=-1;
   int Socket, nBytes;
   LeaseNotify rxBuf;
   struct sockaddr_in serverAddr;
   struct sockaddr_storage serverStorage;
   socklen_t addr_size;
   char atomIP[32] = {0};
   int msgType = 0;
   FILE *cmd = NULL;
   bool gdoNtohl;

   cmd = popen("grep \"ATOM_INTERFACE_IP\" /etc/device.properties | cut -d \"=\" -f2","r");
    if(cmd == NULL) {
       MeshInfo("%s : unable to get the atom IP address",__FUNCTION__);
       return 1;
    }
   fgets(atomIP, sizeof(atomIP), cmd);
   pclose(cmd);
   
   Socket = socket(PF_INET, SOCK_DGRAM, 0);
   /* Coverity Issue Fix - CID:69541 : Negative Returns */
   if( Socket < 0 )
   {	 
	MeshError("%s-%d : Error in opening Socket\n" , __FUNCTION__, __LINE__);
	return ANSC_STATUS_FAILURE;
   }
   serverAddr.sin_family = AF_INET;
   if(!isValidIpAddress(atomIP)) {
   //Receive msgs from the dnsmasq
   MeshInfo("leaseServer Socket bind to localhost\n");
   serverAddr.sin_addr.s_addr = inet_addr(LOCAL_HOST);
   serverAddr.sin_port = htons(47040);
   gdoNtohl = false;
   }
   else
   {
   serverAddr.sin_port = htons(47030);
   serverAddr.sin_addr.s_addr = inet_addr(atomIP);
   gdoNtohl = true;
   }
   rc = memset_s(serverAddr.sin_zero, sizeof(serverAddr.sin_zero), '\0', sizeof(serverAddr.sin_zero));
   ERR_CHK(rc);
    /* Coverity Fix CID :57846 CHECKED _RETURN */
   if( bind(Socket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) != 0)
   {
       MeshError("%s-%d : Error in Binding Socket\n" , __FUNCTION__, __LINE__);
       return -1;
   } 

   addr_size = sizeof serverStorage;
   
   while(1) {
    
     nBytes = recvfrom(Socket,(char *)&rxBuf,sizeof(LeaseNotify),0,(struct sockaddr *)&serverStorage, &addr_size);
     if(gdoNtohl)
      msgType = (int)ntohl(rxBuf.msgType);
     else
      msgType = (int)(rxBuf.msgType);
      
     if(msgType > POD_MAC_POLL)
      Mesh_sendDhcpLeaseUpdate( msgType, rxBuf.lease.mac, rxBuf.lease.ipaddr, rxBuf.lease.hostname, rxBuf.lease.fingerprint);
     else if( msgType == POD_XHS_PORT)
      MeshWarning("Pod is connected on XHS ethernet Port, Unplug and plug in to different one\n");
     else if( msgType == POD_ETH_PORT)
      MeshWarning("Pod is non operational on ethernet port while Ethernet bhaul feature is not enabled\n");
     else if( msgType == POD_ETH_BHAUL)
     {
      MeshInfo("Pod link change detected\n");
      Mesh_logLinkChange();
     }
     else if( msgType == POD_MAC_POLL)
     {
      MeshInfo("Dnsmasq sent poll to retrieve pod mac addresses\n");
      Mesh_SendPodAddresses(); 
     }
     else
      MeshError("%s : Unknown Msg = %d\n", __FUNCTION__, msgType); 
    }
     
   return 0;
}
#if defined(ENABLE_MESH_SOCKETS)

/**
 *  @brief Mesh Agent message queue server thread
 *
 *  This function represents the Mesh Agent's server message queue processing loop. Messages will
 *  continue to be processed until the meshAgent is killed. When we receive a message from the mesh
 *  subprocesses, we will convert it into an RDKB format and send it off to the CcspWiFiAgent.
 *
 *  @return 0
 */
static int msgQServer(void *data)
{
    int master_socket, addrlen, new_socket, activity, i, sd;
    int max_sd;
    struct sockaddr_un address;
    errno_t rc=-1;

    MeshSync rxMsg = {0}; //received message

    //set of socket descriptors
    fd_set readfds;

    //create a master socket
    if( (master_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
        MeshError("Mesh Queue socket creation failure\n");
        return errno;
    }

    //type of socket created
    rc = memset_s(&address, sizeof(address), 0, sizeof(address));
    ERR_CHK(rc);
    address.sun_family = AF_UNIX;

    if (*meshSocketPath == '\0') {
      *address.sun_path = '\0';
      rc = strcpy_s(address.sun_path+1, sizeof(address.sun_path)-1, meshSocketPath+1);
      if(rc != EOK)
      {
          ERR_CHK(rc);
          MeshError("Error in copying meshSocketPath\n");
          return rc;
      }
    } else {
      rc = strcpy_s(address.sun_path, sizeof(address.sun_path), meshSocketPath);
      if(rc != EOK)
      {
          ERR_CHK(rc);
          MeshError("Error in copying meshSocketPath to address.sun_path\n");
          return rc;
      }
      unlink(meshSocketPath);
    }

    //bind the socket
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address))<0)
    {
       /* Coverity  Fix CID:54336 RESOURCE_LEAK */
        close(master_socket);
        MeshError("Mesh Queue socket bind failure\n");
        return errno;
    }

    //try to specify maximum MAX_CONNECTED_CLIENTS pending connections for the master socket
    if (listen(master_socket, MAX_CONNECTED_CLIENTS) < 0)
    {
        MeshError("Mesh Queue socket listen failure\n");
        return errno;
    }

    //accept the incoming connection
    addrlen = sizeof(address);
    MeshInfo("Waiting for connections ...\n");

    while(TRUE)
    {
        //clear the socket set
        FD_ZERO(&readfds);

        //add master socket to set
        FD_SET(master_socket, &readfds);
        max_sd = master_socket;

        //add child sockets to set
        for ( i = 0 ; i < MAX_CONNECTED_CLIENTS ; i++)
        {
            //socket descriptor
            sd = clientSockets[i];

            //if valid socket descriptor then add to read list
            if(sd > 0)
                FD_SET( sd , &readfds);

            //highest file descriptor number, need it for the select function
            if(sd > max_sd)
                max_sd = sd;
        }

        //wait for an activity on one of the sockets , timeout is NULL ,
        //so wait indefinitely
        activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);

        if ((activity < 0) && (errno!=EINTR))
        {
            MeshError("Mesh Queue select error %d\n", errno);
        }

        //If something happened on the master socket ,
        //then its an incoming connection
        if (FD_ISSET(master_socket, &readfds))
        {
            if ((new_socket = accept(master_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)
            {
                MeshError("Mesh Queue accept failure\n");
                return errno;
            }

            //inform user of socket number - used in send and receive commands
            MeshInfo("New Mesh Queue connection, socket fd is %d\n", new_socket);

            //add new socket to array of sockets
            for (i = 0; i < MAX_CONNECTED_CLIENTS; i++)
            {
                //if position is empty
                if( clientSockets[i] == 0 )
                {
                    clientSockets[i] = new_socket;
                    //Prash: Maintain a bitfield to see if any connected
                    clientSocketsMask |= (1 << i);
                    MeshInfo("Adding connected client to list of sockets as %d\n" , i);
                    Mesh_sendDhcpLeaseSync();
                    break;
                }
            }
        }

        // Wait here until the Mesh_sysevent_handler process is ready to accept messages. This is
        // required in the event that the MeshService (Plume) is already running. We don't want to
        // miss any messages. If the SysEventhandler never comes online, we're doomed anyway.
        while (!s_SysEventHandler_ready) {
            sleep(5);
        }

        // Check for I/O operations on client sockets
        for (i = 0; i < MAX_CONNECTED_CLIENTS; i++)
        {
            sd = clientSockets[i];

            if (FD_ISSET( sd , &readfds))
            {
                // clear out the rx buffer before reading
                rc = memset_s((void *)&rxMsg, sizeof(MeshSync), 0, sizeof(MeshSync));
                ERR_CHK(rc);

                //Check if it was for closing, and also read the
                //incoming message
                if (read(sd, (void *) &rxMsg, sizeof(MeshSync)) == 0)
                {
                    //Somebody disconnected , get his details and print
                    getpeername(sd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
                    MeshInfo("Client disconnected fd %d\n", sd);

                    //Close the socket and mark as available in list for reuse
                    close(sd);
                    clientSockets[i] = 0;
                    //Unmask the bit for connected client
                    clientSocketsMask &= ~(1 << i);
                }
                else
                {
                    // Process the received message
                    Mesh_ProcessSyncMessage(rxMsg);
                }
            }
        }
    }

    return 0;
}

/**
 *  @brief Mesh Agent send to client
 *
 *  This function will send a message to the connected clients
 *
 *  @return 0
 */
static int msgQSend(MeshSync *data)
{
    int i;

    // MeshInfo("Entering into %s\n",__FUNCTION__);
    for (i = 0; i < MAX_CONNECTED_CLIENTS; i++)
    {
        int sd = clientSockets[i];

        /* send the message */
        if (sd != 0) {
            if (send(sd, (char *)data, sizeof(MeshSync), 0) == -1)
            {
                MeshError("Error %d sending to client message socket %d\n",errno, sd);
                //Close the socket and mark as available in list for reuse
                close(sd);
                clientSockets[i] = 0;
                clientSocketsMask &= ~(1 << i);
            }
        }
    }

    // MeshInfo("Exiting from %s\n",__FUNCTION__);
    return 0;
}
#else
/**
 *  @brief Mesh Agent message queue server thread
 *
 *  This function represents the Mesh Agent's server message queue processing loop. Messages will
 *  continue to be processed until the meshAgent is killed. When we receive a message from the mesh
 *  subprocesses, we will convert it into an RDKB format and send it off to the CcspWiFiAgent.
 *
 *  @return 0
 */
static int msgQServer(void *data)
{
    // MeshInfo("Entering into %s\n",__FUNCTION__);

    // Start message queue server (communications to mesh processes)
    struct mq_attr qAttr, qAttr_old;
    MeshSync rxMsg = {0};
    unsigned int prio;
    errno_t rc=-1;

    qAttr.mq_flags = 0;
    qAttr.mq_maxmsg = MAX_MESSAGES;
    qAttr.mq_msgsize = sizeof(MeshSync);
    qAttr.mq_curmsgs = 0;

    if ((qd_server = mq_open (MESH_SERVER_QUEUE_NAME, O_RDONLY | O_CREAT, QUEUE_PERMISSIONS, &qAttr)) == -1) {
        // perror ("Server: mq_open (server)");
        MeshError(("Error %d creating server message queue %s\n", errno, MESH_SERVER_QUEUE_NAME));
        return errno;
    }

    // Get the attributes for the server message queue
    mq_getattr (qd_server, &qAttr);
    MeshInfo("%d messages are currently in the server queue\n", qAttr.mq_curmsgs);

    // Eat any previous messages in the queue
    if (qAttr.mq_curmsgs != 0) {

      // First set the queue to not block any calls
      qAttr.mq_flags = O_NONBLOCK;
      mq_setattr (qd_server, &qAttr, &qAttr_old);

      // Eat all of the old messages
      while (mq_receive (qd_server, (char *) &rxMsg, sizeof(MeshSync), &prio) != -1)
        MeshInfo ("Received a message with priority %d.\n", prio);

      // The call failed.  Make sure errno is EAGAIN
      if (errno != EAGAIN) {
        MeshError(("Error %d reading messages from %s\n", errno, MESH_SERVER_QUEUE_NAME));
        return errno;
      }

      // Now restore the attributes
      mq_setattr (qd_server, &qAttr_old, 0);
    }

    // Wait here until the Mesh_sysevent_handler process is ready to accept messages. This is
    // required in the event that the MeshService (Plume) is already running. We don't want to
    // miss any messages. If the SysEventHandler never comes online, we're doomed anyway.
    while (!s_SysEventHandler_ready) {
        sleep(5);
    }

    for (;;)
    {
        // clear out the rx buffer before reading
        rc = memset_s((void *)&rxMsg, sizeof(MeshSync), 0, sizeof(MeshSync));
        ERR_CHK(rc);

        // get the oldest message with highest priority
        if (mq_receive (qd_server, (char *) &rxMsg, sizeof(MeshSync), NULL) == -1) {
            // perror ("Server: mq_receive");
            MeshError("Error %d receiving message from queue %s\n", errno, MESH_SERVER_QUEUE_NAME);
            break; // kick out of loop and clean up
        }

        // Process the received message
        Mesh_ProcessSyncMessage(rxMsg);
    }

    // Tear down the message queue
    mq_close(qd_server);
    mq_unlink(MESH_SERVER_QUEUE_NAME);

    // MeshInfo("Exiting from %s\n",__FUNCTION__);
    return 0;
}


/**
 *  @brief Mesh Agent send to client
 *
 *  This function will send a message to the client message queue
 *
 *  @return 0
 */
static int msgQSend(MeshSync *data)
{
    // MeshInfo("Entering into %s\n",__FUNCTION__);
    mqd_t qd_client;
    struct mq_attr attr;

    if ((qd_client = mq_open (MESH_CLIENT_QUEUE_NAME, O_WRONLY)) == -1) {
        //MeshError("Error %d connecting to client msgQueue %s\n", errno, MESH_CLIENT_QUEUE_NAME);
        return errno;
    }

    // Get the attributes for the client message queue
    mq_getattr (qd_client, &attr);
    if (attr.mq_curmsgs > 0) {
        MeshInfo("%d messages are currently in the client queue\n", attr.mq_curmsgs);
    }

    /* send the message */
    if (mq_send(qd_client, (char *)data, sizeof(MeshSync), 0) == -1)
    {
        MeshError("Error %d sending to client msgQueue %s\n",errno, MESH_CLIENT_QUEUE_NAME);
    }

       /* cleanup */
    if (mq_close(qd_client) == -1)
    {
        MeshError("Error %d closing msgQueue to client\n", errno);
    }

    // MeshInfo("Exiting from %s\n",__FUNCTION__);
    return 0;
}
#endif

/**
 * @brief Mesh Agent Get Url
 *
 * This function will set the url and notify the Mesh vendor of the change
 */
int Mesh_GetUrl(char *retBuf, int bufSz)
{
    static unsigned char out_val[128];
    errno_t rc = -1;

    // MeshInfo("Entering into %s\n",__FUNCTION__);

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr("mesh_url", out_val, sizeof(out_val)) != 0)
    {
        // syscfg value is blank, send url default value
        rc = strcpy_s(out_val, sizeof(out_val), urlDefault);
        if(rc != EOK)
        {
           ERR_CHK(rc);
           MeshError("Error in copying url default value\n");
           return false;
        }
    }
    rc = strcpy_s(retBuf, bufSz, out_val);
    if(rc != EOK)
    {
        ERR_CHK(rc);
        MeshError("Error in copying url value\n");
        return false;
    }
    return true;
}

/**
 * @brief Mesh Agent Set Url
 *
 * This function will set the url and notify the Mesh vendor of the change
 */
bool Mesh_SetUrl(char *url, bool init)
{
    unsigned char outBuf[128] = {0};
    errno_t rc       = -1;
    int     ind      = -1;
    bool success = TRUE;

    // MeshInfo("Entering into %s\n",__FUNCTION__);

    Mesh_GetUrl(outBuf, sizeof(outBuf));
    // If the url value is different, set the syscfg value and notify the mesh vendor
    rc = strcmp_s(url,strlen(url),outBuf,&ind);
    ERR_CHK(rc);
    if (init || ((rc == EOK) && (ind != 0)))
    {
        PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;
        // Update the data model
        rc = strcpy_s(g_pMeshAgent->meshUrl, sizeof(g_pMeshAgent->meshUrl), url);
        if(rc != EOK)
        {
           ERR_CHK(rc);
           MeshError("Error in copying url to data model g_pMeshAgent->meshUrl\n");
           return FALSE;
        }
        MeshSync mMsg = {0};
        // update the syscfg database
        Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_URL_CHANGE].sysStr, url, false);
        // Notify plume
        // Set sync message type
        mMsg.msgType = MESH_URL_CHANGE;
        rc = strcpy_s(mMsg.data.url.url, sizeof(mMsg.data.url.url), url);
        if(rc != EOK)
        {
            ERR_CHK(rc);
            MeshError("Error in copying url to mMsg.data.url.url\n");
            return FALSE;
        }
        // We filled our data structure so we can send it off
        msgQSend(&mMsg);

        MeshInfo("Meshwifi URL is set to %s\n", g_pMeshAgent->meshUrl);

        // Send sysevent notification
        /* Coverity Fix CID:66684 DC.STRING_BUFFER */
        snprintf(outBuf,sizeof(outBuf), "MESH|%s", url);
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_URL_CHANGE].sysStr, outBuf, 0, false);
    }

    return success;
}

/**
 * @brief Mesh Agent Get State
 *
 * This function will return the mesh state
 */
eMeshStateType Mesh_GetMeshState()
{
    unsigned char out_val[128];
    errno_t rc       = -1;
    int     ind      = -1;
    eMeshStateType state = MESH_STATE_FULL;

    // MeshInfo("Entering into %s\n",__FUNCTION__);

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_STATE_CHANGE].sysStr, out_val, sizeof(out_val)) == 0)
    {
        rc = strcmp_s(meshStateArr[MESH_STATE_MONITOR].mStr,strlen(meshStateArr[MESH_STATE_MONITOR].mStr),out_val,&ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK))
        {
            state = MESH_STATE_MONITOR;
        }
    }

    return state;
}


/**
 * @brief Mesh Agent Set State
 *
 * This function will set the mesh state and notify the mesh components
 */
bool Mesh_SetMeshState(eMeshStateType state, bool init, bool commit)
{
    // MeshInfo("Entering into %s\n",__FUNCTION__);

    unsigned char outBuf[128];
    MeshSync mMsg = {0};
    bool success = TRUE;

    // MeshInfo("Entering into %s\n",__FUNCTION__);

    // If the state value is different or this is during setup - make it happen.
    if (init || Mesh_GetMeshState() != state)
    {
        MeshInfo("Meshwifi state is set to %s\n", meshStateArr[state].mStr);
        PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;
        // Update the data model
        g_pMeshAgent->meshState = state;
        
        if(commit)
        {
         /* Coverity Fix CID:55887 CHECKED_RETURN */
         if( Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_STATE_CHANGE].sysStr, meshStateArr[state].mStr, true) != ANSC_STATUS_SUCCESS )
            MeshError(" %s-%d Failed in  Mesh_SysCfgSetStr()\n",__FUNCTION__,__LINE__);       
        }
        // Notify plume
        // Set sync message type
        mMsg.msgType = MESH_STATE_CHANGE;
        mMsg.data.meshState.state = state;

        // We filled our data structure so we can send it off
        msgQSend(&mMsg);

        // Send sysevent notification
        /* Coverity Fix CID: 71888 DC.STRING_BUFFER */
        snprintf(outBuf,sizeof(outBuf), "MESH|%s", meshStateArr[state].mStr);
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_STATE_CHANGE].sysStr, outBuf, 0, true);
    }

    return success;
}

/**
 * @brief Mesh Agent Get Enable/Disable
 *
 * This function will return whther or not the mesh service is enabled
 */
bool Mesh_GetEnabled(const char *name)
{
    unsigned char out_val[128];
    errno_t rc       = -1;
    int     ind      = -1;
    bool enabled = false;

    // MeshInfo("Entering into %s\n",__FUNCTION__);

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(name, out_val, sizeof(out_val)) == 0)
    {
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((!ind) && (rc == EOK))
        {
            enabled = true;
        }
    }

    return enabled;
}

void changeChBandwidth(int radioId, int channelBw) {
  CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
  parameterValStruct_t   param_val[1];
  char parameterName[256] = {0};
  char parameterValue[16] = {0};
  char  component[256]  = "eRT.com.cisco.spvtg.ccsp.wifi";
  char  bus[256]        = "/com/cisco/spvtg/ccsp/wifi";
  char* faultParam      = NULL;
  int   ret             = 0;

  sprintf(parameterName, "Device.WiFi.Radio.%d.OperatingChannelBandwidth", radioId+1); 
  sprintf(parameterValue, "%dMHz", channelBw); 
  
  param_val[0].parameterName=parameterName;
  param_val[0].parameterValue=parameterValue;
  param_val[0].type = ccsp_string;

  MeshInfo("RDK_LOG_WARN, %s-%d [set %s %s] \n",__FUNCTION__,__LINE__, parameterName, parameterValue);

    ret = CcspBaseIf_setParameterValues(
            bus_handle,
            component,
            bus,
            0,
            0,
            &param_val,
            1,
            TRUE,
            &faultParam
            );

    if( ( ret != CCSP_SUCCESS ) && ( faultParam!=NULL )) {
        MeshError(" %s-%d Failed to set %s\n",__FUNCTION__,__LINE__, parameterName);
        bus_info->freefunc( faultParam );
        return FALSE;
    }
    return TRUE;
}

BOOL set_wifi_boolean_enable(char *parameterName, char *parameterValue) {
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterValStruct_t   param_val[1];
    char  component[256]  = "eRT.com.cisco.spvtg.ccsp.wifi";
    char  bus[256]        = "/com/cisco/spvtg/ccsp/wifi";
    char* faultParam      = NULL;
    int   ret             = 0;

    param_val[0].parameterName=parameterName;
    param_val[0].parameterValue=parameterValue;
    param_val[0].type = ccsp_boolean;

    MeshInfo("RDK_LOG_WARN, %s-%d [set %s %s] \n",__FUNCTION__,__LINE__, parameterName, parameterValue);

    ret = CcspBaseIf_setParameterValues(
            bus_handle,
            component,
            bus,
            0,
            0,
            &param_val,
            1,
            TRUE,
            &faultParam
            );

    if( ( ret != CCSP_SUCCESS ) && ( faultParam!=NULL )) {
        MeshError(" %s-%d Failed to set %s\n",__FUNCTION__,__LINE__, parameterName);
        bus_info->freefunc( faultParam );
        return FALSE;
    }
    return TRUE;
}

BOOL is_band_steering_enabled()
{
    int ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char dstComponent[64]="eRT.com.cisco.spvtg.ccsp.wifi";
    char dstPath[64]="/com/cisco/spvtg/ccsp/wifi";
    char *paramNames[]={"Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Enable"};
    int  valNum = 0;
    errno_t rc = -1;
    int ind = -1;

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            1,
            &valNum,
            &valStructs);

    if(CCSP_Message_Bus_OK != ret)
    {
         CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return FALSE;
    }

    MeshWarning("valStructs[0]->parameterValue = %s\n",valStructs[0]->parameterValue);

    rc = strcmp_s("true",strlen("true"),valStructs[0]->parameterValue,&ind);
    ERR_CHK(rc);
    if((ind == 0) && (rc == EOK))   {
        free_parameterValStruct_t(bus_handle, valNum, valStructs);
        return TRUE;
    }
    else
    {
        free_parameterValStruct_t(bus_handle, valNum, valStructs);
        return FALSE;
    }
}

BOOL is_reset_needed()
{
    int ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char dstComponent[64]="eRT.com.cisco.spvtg.ccsp.wifi";
    char dstPath[64]="/com/cisco/spvtg/ccsp/wifi";
    const char ap12[]="Device.WiFi.SSID.13.Enable";
    const char ap13[]="Device.WiFi.SSID.14.Enable";
    char *paramNames[]={ap12,ap13};
    int  valNum = 0;
    BOOL ret_b=FALSE;
    errno_t rc[2] = {-1, -1};
    int ind[2] = {-1, -1};

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            2,
            &valNum,
            &valStructs);

    if(CCSP_Message_Bus_OK != ret){
         CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return FALSE;
    }

    if(valStructs)
    {
	rc[0] = strcmp_s("true",strlen("true"),valStructs[0]->parameterValue,&ind[0]);
        ERR_CHK(rc[0]);
        rc[1] = strcmp_s("true",strlen("true"),valStructs[1]->parameterValue,&ind[1]);
        ERR_CHK(rc[1]);
	if (((ind[0] == 0 ) && (rc[0] == EOK)) || ((ind[1] == 0) && (rc[1] == EOK)))
	{
            MeshInfo("Mesh interfaces are up, Need to disable them\n");
            t2_event_d("WIFI_INFO_MeshDisabled_syscfg0", 1);
            ret_b=(valStructs?true:false);
	}
    }

    if(valStructs)
     MeshWarning("valStructs[0]->parameterValue = %s valStructs[1]->parameterValue = %s \n",valStructs[0]->parameterValue,valStructs[1]->parameterValue);

    free_parameterValStruct_t(bus_handle, valNum, valStructs);
    return ret_b;
}

//Enables/Disables Mesh APs, If enable, sets ath12 and ath13 and does apply wifi setting, when mesh
//Disabled , it bring downs Vaps
void set_mesh_APs(bool enable)
{
 MeshInfo("%s Performing a mesh AP = %s\n",__FUNCTION__,(enable?"true":"false"));
 if(set_wifi_boolean_enable("Device.WiFi.SSID.13.Enable",(enable?"true":"false")))
  MeshInfo("Device.WiFi.SSID.13.Enable succesfully set to %s\n",(enable?"true":"false"));
 if(set_wifi_boolean_enable("Device.WiFi.SSID.14.Enable",(enable?"true":"false")))
  MeshInfo("Device.WiFi.SSID.14.Enable succesfully set to %s\n",(enable?"true":"false"));
}

BOOL is_SSID_enabled()
{
    int ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char dstComponent[64]="eRT.com.cisco.spvtg.ccsp.wifi";
    char dstPath[64]="/com/cisco/spvtg/ccsp/wifi";
    const char ap12[]="Device.WiFi.SSID.13.Status";
    const char ap13[]="Device.WiFi.SSID.14.Status";
    char *paramNames[]={ap12,ap13};
    int  valNum = 0;
    BOOL ret_b=FALSE;
    errno_t rc = -1;
    int ind = -1;
    int ifaceDown = 0;

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            2,
            &valNum,
            &valStructs);

    if(CCSP_Message_Bus_OK != ret){
         CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return FALSE;
    }

    if(valStructs)
    {
	rc = strcmp_s("Down",strlen("Down"),valStructs[0]->parameterValue,&ind);
        ERR_CHK(rc);
	if((ind ==0 ) && (rc == EOK)) 
	{
	     ifaceDown = 1;
	}
	else 
	{
	     rc = strcmp_s("Down",strlen("Down"),valStructs[1]->parameterValue,&ind);
             ERR_CHK(rc);
	     if((ind ==0 ) && (rc == EOK)) 
	     {
		   ifaceDown = 1;
	     }
	}
    }
	
	if(ifaceDown)
        MeshInfo("Mesh interfaces are Down \n");
    else
         ret_b=(valStructs?true:false);

    if(valStructs)
     MeshWarning("valStructs[0]->parameterValue = %s valStructs[1]->parameterValue = %s \n",valStructs[0]->parameterValue,valStructs[1]->parameterValue);

    free_parameterValStruct_t(bus_handle, valNum, valStructs);
    return ret_b;
}

void is_xf3_platform()
{
    FILE *cmd;
    char platform[32] = {'\0'};
    int ind = -1;

    cmd = popen("grep \"BOX_TYPE\" /etc/device.properties | cut -d \"=\" -f2","r");
    if(cmd == NULL) {
        MeshInfo("Mesh BOX_TYPE fetch failed \n");
        return;
    }
    fgets(platform, sizeof(platform), cmd);
    pclose(cmd);
    platform[strlen(platform) -1] = '\0';
    ind = strcmp(XF3_PLATFORM,platform);
    if ( ind ==0 )
    {
        isPaceXF3 = true;
    }
    MeshInfo("Is XF3 platform check is = %d\n",isPaceXF3);
}

BOOL radio_check()
{
    int ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char dstComponent[64]="eRT.com.cisco.spvtg.ccsp.wifi";
    char dstPath[64]="/com/cisco/spvtg/ccsp/wifi";
    int  valNum = 0;
    BOOL ret_b=FALSE;
    int ind = -1;
    errno_t rc = -1;
    int radioDown = 0;
    char radio1[64] = {0};
    char radio2[64] = {0};
    char state[10] = {0};

    sprintf(radio1, "%s", isPaceXF3 ? RADIO_ENABLE_24 : RADIO_STATUS_24);
    sprintf(radio2, "%s", isPaceXF3 ? RADIO_ENABLE_50 : RADIO_STATUS_50);
    sprintf(state, "%s", isPaceXF3 ?  STATE_FALSE : STATE_DOWN);

    char *paramNames[]={radio1,radio2};

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            2,
            &valNum,
            &valStructs);

    if(CCSP_Message_Bus_OK != ret){
         CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return FALSE;
    }

    if(valStructs)
    {

            rc = strcmp_s(state,strlen(state),valStructs[0]->parameterValue,&ind);
            ERR_CHK(rc);
            if ((ind ==0 ) && (rc == EOK)) 
            {
                radioDown = 1;
            }
            else
            {
                rc = strcmp_s(state,strlen(state),valStructs[1]->parameterValue,&ind);
                ERR_CHK(rc);
                if ((ind ==0 ) && (rc == EOK)) 
		{
		    radioDown = 1;
		}
			
	    }
	
    }
	
    if(radioDown)
        MeshError("Radio Error: Status 2.4= %s 5= %s \n", valStructs[0]->parameterValue, valStructs[1]->parameterValue);
    else
         ret_b=(valStructs?true:false);

    if(valStructs)
     MeshWarning("valStructs[0]->parameterValue = %s valStructs[1]->parameterValue = %s \n",valStructs[0]->parameterValue,valStructs[1]->parameterValue);

    free_parameterValStruct_t(bus_handle, valNum, valStructs);
    if(!ret_b) {
      MeshError(("MESH_ERROR:Fail to enable Mesh because either one of the radios are off\n"));
      t2_event_d("WIFI_ERROR_MESH_FAILED", 1);      
    }
    
    return ret_b;
}

BOOL is_bridge_mode_enabled()
{
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char dstComponent[64]="eRT.com.cisco.spvtg.ccsp.pam";
    char dstPath[64]="/com/cisco/spvtg/ccsp/pam";
    char *paramNames[]={"Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode"};
    int  valNum = 0;
    errno_t rc[2] = {-1, -1};
    int ind[2] = {-1, -1};

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            1,
            &valNum,
            &valStructs);

    if(CCSP_Message_Bus_OK != ret)
    {
         CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return FALSE;
    }

    MeshWarning("valStructs[0]->parameterValue = %s\n",valStructs[0]->parameterValue);

    rc[0] = strcmp_s("bridge-static",strlen("bridge-static"),valStructs[0]->parameterValue,&ind[0]);
    ERR_CHK(rc[0]);
    rc[1] = strcmp_s("full-bridge-static",strlen("full-bridge-static"),valStructs[0]->parameterValue,&ind[1]);
    ERR_CHK(rc[1]);
    if(((ind[0] == 0 ) && (rc[0] == EOK)) || ((ind[1] == 0) && (rc[1] == EOK)))
    {
         MeshError("Brigde mode enabled, setting mesh wifi to disabled \n");
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return TRUE;
    }
    else
    {
        free_parameterValStruct_t(bus_handle, valNum, valStructs);
        return FALSE;
    }

}

void meshSetEthbhaulSyscfg(bool enable)
{
    int i =0;

    MeshInfo("%s Setting eth bhaul enable in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_RFC_UPDATE].sysStr, (enable?"true":"false"), true) != 0) {
         MeshInfo("Failed to set the Eth Bhaul Enable in syscfg, retrying 5 times\n");
         for(i=0; i<5; i++) {
         if(!Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_RFC_UPDATE].sysStr, (enable?"true":"false"), true)) {
           MeshInfo("eth bhaul syscfg set passed in %d attempt\n", i+1);
           break;
         }
         else
          MeshInfo("eth bhaul syscfg set retrial failed in %d attempt\n", i+1);
      }
   }
   else
    MeshInfo("eth bhaul enable set in the syscfg successfully\n");
}

bool meshSetGreAccSyscfg(bool enable)
{
    int i = 0;
    bool success = false;

    MeshInfo("%s Setting GRE_ACC enable in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr("mesh_gre_acc_enable", (enable?"true":"false"), true) != 0)
    {
        MeshInfo("Failed to set the GRE_ACC Enable in syscfg, retrying 5 times\n");
        for(i=0; i<5; i++)
        {
            if(!Mesh_SysCfgSetStr("mesh_gre_acc_enable", (enable?"true":"false"), true))
            {
                MeshInfo("GRE_ACC syscfg set passed in %d attempt\n", i+1);
                success = true;
                break;
             }
             else
             {
                 MeshInfo("GRE_ACC syscfg set retrial failed in %d attempt\n", i+1);
             }
        }
    }
    else
    {
        MeshInfo("GRE_ACC enable set in the syscfg successfully\n");
        success = true;
    }

    return success;
}

bool meshSetOVSSyscfg(bool enable)
{
    int i = 0;
    bool success = false;

    MeshInfo("%s Setting OVS enable in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr("mesh_ovs_enable", (enable?"true":"false"), true) != 0)
    {
        MeshInfo("Failed to set the OVS Enable in syscfg, retrying 5 times\n");
        for(i=0; i<5; i++)
        {
            if(!Mesh_SysCfgSetStr("mesh_ovs_enable", (enable?"true":"false"), true))
            {
                MeshInfo("ovs syscfg set passed in %d attempt\n", i+1);
                success = true;
                break;
            }
            else
            {
                MeshInfo("ovs syscfg set retrial failed in %d attempt\n", i+1);
            }
        }
    }
    else
    {
        MeshInfo("ovs enable set in the syscfg successfully\n");
        success = true;
    }

    return success;
}

void meshSetSyscfg(bool enable)
{
    int i =0;
    FILE *fpMeshFile = NULL;

    MeshInfo("%s Setting mesh enable in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr, (enable?"true":"false"), true) != 0) {
         MeshInfo("Failed to set the Mesh Enable in syscfg, retrying 5 times\n");
         for(i=0; i<5; i++) {
         if(!Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr, (enable?"true":"false"), true)) {
           MeshInfo("syscfg set passed in %d attempt\n", i+1);
           break;
         }
         else{
          MeshInfo("syscfg set retrial failed in %d attempt\n", i+1);
          t2_event_d("SYS_ERROR_SyscfgSet_retry_failed",  1); 
         }
      }
   }
   else
    MeshInfo("mesh enable set in the syscfg successfully\n");

  if(enable) { 
    MeshInfo("Set the flag in persistent memory for syscfg error recovery\n");
    fpMeshFile = fopen(MESH_ENABLED ,"a");
    if (fpMeshFile)
        fclose(fpMeshFile);
    else
        MeshInfo("fpMeshFile is NULL\n");
  } else
  {
   if(!remove(MESH_ENABLED)) 
    MeshInfo("Mesh Flag removed from persistent memory\n");
   else
    MeshError("Failed to remove Mesh Flag from persistent memory\n");
  }
}

/**
 * @brief Mesh Agent EthBhaul Set Enable/Disable
 *
 * This function will enable/disable the Mesh Pod ethernet backhaul feature enable/disable
 */
bool Mesh_SetMeshEthBhaul(bool enable, bool init)
{
    char cmd[256] = {0};
    int rc = -1;
    // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled(meshSyncMsgArr[MESH_RFC_UPDATE].sysStr) != enable)
    {
        meshSetEthbhaulSyscfg(enable);
        g_pMeshAgent->PodEthernetBackhaulEnable = enable;
        //Send this as an RFC update to plume manager
        Mesh_sendRFCUpdate("PodEthernetBackhaul.Enable", enable ? "true" : "false", rfc_boolean);
    // If ethernet bhaul is disabled, send msg to dnsmasq informing same with a dummy mac    
        if(!enable)
        {
          sprintf(cmd,"%s %s", ETHBHAUL_SWITCH, "-eb_disable &");
          rc = system(cmd);
          if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
          {
              MeshError("%s: Ethernet backhaul disable failed = %d\n", cmd, WEXITSTATUS(rc));
          }

          Mesh_SendEthernetMac("00:00:00:00:00:00");
        }
    }
    return TRUE;
}

/**
 * @brief Mesh Agent GREAcceleration Set Enable/Disable
 *
 * This function will enable/disable the GRE acceleration mode
 */
bool Mesh_SetGreAcc(bool enable, bool init)
{
    // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled("mesh_gre_acc_enable") != enable)
    {
        if (enable && Mesh_GetEnabled("mesh_ovs_enable"))
        {   // mesh_ovs_enable has higher priority over mesh_gre_acc_enable,
            // therefore when ovs is enabled, disable gre acc.
            MeshWarning("Disabling GreAcc RFC, since OVS is currently enabled!\n");
            enable = false;
        }
        if (!meshSetGreAccSyscfg(enable))
        {
            MeshError("Unable to %s GreAcc RFC\n", (enable?"enable":"disable"));
            return false;
        }
        g_pMeshAgent->GreAccEnable = enable;

        //Send this as an RFC update to plume manager
        if(enable)
        {
            MeshInfo("GreAcc_RFC_changed_to_enabled\n");
        }
        else
        {
            MeshInfo("GreAcc_changed_to_disabled\n");
        }
        Mesh_sendRFCUpdate("GRE_ACC.Enable", enable ? "true" : "false", rfc_boolean);
    }
    return true;
}

/**
 * @brief Mesh Agent OpenvSwitch Set Enable/Disable
 *
 * This function will enable/disable the OpenvSwitch mode
 */
bool Mesh_SetOVS(bool enable, bool init)
{
    // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled("mesh_ovs_enable") != enable)
    {
        if (enable)
        {
            if (!Mesh_GetEnabled(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr))
            {
                MeshWarning("Disabling OVS RFC, since mesh is currently disabled!\n");
                enable = false;
            }
            else if (Mesh_GetEnabled("mesh_gre_acc_enable"))
            {   // mesh_ovs_enable has higher priority over mesh_gre_acc_enable,
                // therefore disable Gre Acc.
                Mesh_SetGreAcc(false, false);
            }
        }
        if (!meshSetOVSSyscfg(enable))
        {
            MeshError("Unable to %s OVS RFC\n", (enable?"enable":"disable"));
            return false;
        }
        g_pMeshAgent->OvsEnable = enable;

        //Send this as an RFC update to plume manager
        if(enable)
        {
            MeshInfo("OVS_RFC_changed_to_enabled\n");
        }
        else
        {
            MeshInfo("OVS_RFC_changed_to_disabled\n");
        }
        Mesh_sendRFCUpdate("OVS.Enable", enable ? "true" : "false", rfc_boolean);
    }
    return true;
}

int getMeshErrorCode()
{
    return meshError;
}

void handleMeshEnable(void *Args)
{
	bool success = TRUE;
        bool enable = FALSE;
	unsigned char outBuf[128];
        static bool last_set = FALSE;
        int error = MB_OK;
        int err = 0;
        int i = 0;
        unsigned char bit_mask =  (unsigned char) Args;

        pthread_mutex_lock(&mesh_handler_mutex);
        enable = (bit_mask & 0x02) ? TRUE : FALSE;
        if (bit_mask & 0x01)
        {
            pthread_detach(pthread_self());
        }
        MeshInfo("last_set= %d, enable = %d\n",last_set,enable);
        if(last_set == enable)
        {
            MeshInfo("Skipping mesh redundant set\n");
            meshError = MB_OK;
            pthread_mutex_unlock(&mesh_handler_mutex);
            return;
        }

	 if (enable) {
            // This will only work if this service is started *AFTER* CcspWifi
            // If the service is not running, start it
            if(!radio_check() || is_bridge_mode_enabled()) {
              MeshError("Mesh Pre-check conditions failed, setting mesh wifi to disabled \n");
              error =  MB_ERROR_PRECONDITION_FAILED;
              meshSetSyscfg(0);
              pthread_mutex_unlock(&mesh_handler_mutex);
              return FALSE;
            }
	    if(is_band_steering_enabled()) {
                   if(set_wifi_boolean_enable("Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Enable", "false")==FALSE) {
                        MeshError(("MESH_ERROR:Fail to enable Mesh because fail to turn off Band Steering\n"));
                        error =  MB_ERROR_BANDSTEERING_ENABLED;
                        meshSetSyscfg(0);
                        pthread_mutex_unlock(&mesh_handler_mutex);
                        return FALSE;
                   }
            }

            MeshInfo("Checking if Mesh APs are enabled or disabled\n");
            if(is_SSID_enabled())
                MeshInfo("Mesh interfaces are up\n");
            else
            {
                MeshInfo("Turning Mesh SSID enable\n");
                set_mesh_APs(true);
            }
            if ((err = svcagt_get_service_state(meshServiceName)) == 0)
            {
                // returns "0" on success
                if ((err = svcagt_set_service_state(meshServiceName, true)) != 0)
                {
                    MeshError("meshwifi service failed to run, igonoring the mesh enablement\n");
		    t2_event_d("WIFI_ERROR_meshwifiservice_failure", 1);
                    error = MB_ERROR_MESH_SERVICE_START_FAIL;
                    meshSetSyscfg(0);
                    success = FALSE;
                }
            }
        } else {
            // This will only work if this service is started *AFTER* CcspWifi
            // If the service is running, stop it
            if ((err = svcagt_get_service_state(meshServiceName)) == 1)
            {
                // returns "0" on success
                if ((err = svcagt_set_service_state(meshServiceName, false)) != 0)
                {
                    meshSetSyscfg(0);
                    error = MB_ERROR_MESH_SERVICE_STOP_FAIL;
                    success = FALSE;
                }
            }
        }

        if (success) {
            //MeshInfo("Meshwifi has been %s\n",(enable?"enabled":"disabled"));
            MeshInfo("MESH_STATUS:%s\n",(enable?"enabled":"disabled"));

            PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;
            // Update the data model
            g_pMeshAgent->meshEnable = enable;
            g_pMeshAgent->meshStatus = (enable?MESH_WIFI_STATUS_INIT:MESH_WIFI_STATUS_OFF);
            // Send sysevent notification
            /*Coverity Fix CID:69958 DC.STRING_BUFFER */
            snprintf(outBuf,sizeof(outBuf), "MESH|%s", (enable?"true":"false"));
            Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr, outBuf, 0, true);
            /*Coverity Fix CID:69958 DC.STRING_BUFFER */
            snprintf(outBuf,sizeof(outBuf), "MESH|%s", meshWifiStatusArr[(enable?MESH_WIFI_STATUS_INIT:MESH_WIFI_STATUS_OFF)].mStr);
            Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_STATUS].sysStr, outBuf, 0, true);
        } else {
            MeshError("Error %d %s Mesh Wifi\n", err, (enable?"enabling":"disabling"));
            if ((err == 0x100) && (enable == TRUE)) {
            	t2_event_d("SYS_INFO_MESHWIFI_DISABLED", 1);
	    }
        }
   last_set = enable;
   if (!(bit_mask & 0x01))
   {
       meshError = error;
   }
   pthread_mutex_unlock(&mesh_handler_mutex);

   return NULL;
}

/**
 * @brief Mesh Agent Set Enable/Disable
 *
 * This function will enable/disable the Mesh service
 */
bool Mesh_SetEnabled(bool enable, bool init)
{
    // MeshInfo("Entering into %s\n",__FUNCTION__);
    bool success = true;
    unsigned char bit_mask = 1;

    // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr) != enable)
    {
        if (!enable)
        {   // if mesh is being disabled, then also disable ovs
            MeshWarning("Disabling OVS RFC, since mesh will be disabled!\n");
            Mesh_SetOVS(false, false);
        }
        meshSetSyscfg(enable);
 	pthread_t tid;
        if(enable)
        {
            bit_mask = bit_mask | 0x2;
        }
	pthread_create(&tid, NULL, &handleMeshEnable, (void*)bit_mask);

    }

    return success;
}

BOOL is_radio_enabled(char *dcs1, char *dcs2)
{
    int ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char dstComponent[64]="eRT.com.cisco.spvtg.ccsp.wifi";
    char dstPath[64]="/com/cisco/spvtg/ccsp/wifi";
    char *paramNames[]={dcs1,dcs2};
    int  valNum = 0;
    BOOL ret_b=FALSE;
    errno_t rc = -1;
    int ind = -1;

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            2,
            &valNum,
            &valStructs);

    if(CCSP_Message_Bus_OK != ret){
         CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return FALSE;
    }

    MeshWarning("valStructs[0]->parameterValue = %s valStructs[1]->parameterValue = %s \n",valStructs[0]->parameterValue,valStructs[1]->parameterValue);
    rc = strcmp_s("false",strlen("false"),valStructs[0]->parameterValue,&ind);
    ERR_CHK(rc);
    if((ind ==0 ) && (rc == EOK)) 
        dcs1[0]=0;
    else
	ret_b=TRUE;

    rc = strcmp_s("false",strlen("false"),valStructs[1]->parameterValue,&ind);
    ERR_CHK(rc);
    if((ind ==0 ) && (rc == EOK)) 
        dcs2[0]=0;
    else
        ret_b=TRUE;

    free_parameterValStruct_t(bus_handle, valNum, valStructs);
    return ret_b;
}

BOOL is_DCS_enabled()
{
    if(is_radio_enabled("Device.WiFi.Radio.1.X_RDKCENTRAL-COM_DCSEnable","Device.WiFi.Radio.2.X_RDKCENTRAL-COM_DCSEnable") 
          || is_radio_enabled("Device.WiFi.Radio.1.X_COMCAST-COM_DCSEnable","Device.WiFi.Radio.2.X_COMCAST-COM_DCSEnable")) 
    {
        return TRUE;
    }
    return FALSE;
}

/**
 * Prash: This is a last option if all syscfg and retrial fails
 *
 */
static void Mesh_Recovery()
{
    if(!access(MESH_ENABLED, F_OK)) {
     MeshInfo("mesh flag is enabled in nvram, setting mesh enabled\n");
     Mesh_SetEnabled(true, true);
    } else
    {
     MeshInfo("mesh flag not found in nvram, setting mesh disabled\n");
     Mesh_SetEnabled(false, true);
    }
}
/**
 * @brief Mesh Agent set default values
 *
 * This function will fetch and set the default values for the mesh agent.
 *
 */
static void Mesh_SetDefaults(ANSC_HANDLE hThisObject)
{
    unsigned char out_val[128];
    errno_t rc = -1, rc1 = -1;
    int     ind = -1, ind1 = -1;
    int i = 0;
    FILE *cmd=NULL;
    char mesh_enable[16];

    PCOSA_DATAMODEL_MESHAGENT pMyObject = (PCOSA_DATAMODEL_MESHAGENT) hThisObject;

    // Check to see if the mesh dev flag is set
    bool devFlag = (access(meshDevFile, F_OK) == 0);
    //Fetch device name, this temporary fix should be removed when RDKB-31468 ticket is fixed
    is_xf3_platform();
    // set URL
    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_URL_CHANGE].sysStr, out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Mesh Url not set, using default %s\n", urlDefault);
        Mesh_SetUrl(urlDefault, true);
    } else {
        rc = strcmp_s(out_val, strlen(out_val), urlOld, &ind);
        ERR_CHK(rc);
        if (!devFlag && ((ind == 0) && (rc == EOK)))
        {
            // Using the old value, reset to new default
            MeshInfo("Mesh url was using old value, updating to %s\n", urlDefault);
            Mesh_SetUrl(urlDefault, true);
        }
        else
        {
            if (devFlag) {
                MeshInfo("Mesh dev specified, url not changed %s\n", out_val);
            } else {
                MeshInfo("Mesh url is %s\n", out_val);
            }
            unsigned char outBuf[128];
            rc = strcpy_s(pMyObject->meshUrl, sizeof(pMyObject->meshUrl), out_val);
            if(rc != EOK)
            {
                ERR_CHK(rc);
                MeshError("Error in copying Mesh url to pMyObject->meshUrl\n");
                return;
            }
            // Send sysevent notification
            /* Coverity Fix CID:65429 DC.STRING_BUFFER */
            snprintf(outBuf,sizeof(outBuf), "MESH|%s", out_val);
            Mesh_SyseventSetStr(meshSyncMsgArr[MESH_URL_CHANGE].sysStr, outBuf, 0, false);
        }
    }

    // set Mesh State
    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_STATE_CHANGE].sysStr, out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg error, Setting initial mesh state to Full\n");
        Mesh_SetMeshState(MESH_STATE_FULL, true, true);
    }
    else
    {
        rc = strcmp_s(out_val, strlen(out_val), meshStateArr[MESH_STATE_FULL].mStr, &ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK))
        {
            MeshInfo("Setting initial mesh state to Full\n");
            Mesh_SetMeshState(MESH_STATE_FULL, true, false);
        }
        else
        {
            rc = strcmp_s(out_val, strlen(out_val), meshStateArr[MESH_STATE_MONITOR].mStr, &ind);
            ERR_CHK(rc);
            if((ind == 0) && (rc == EOK))
            {
                MeshInfo("Setting initial mesh state to Monitor\n");
                Mesh_SetMeshState(MESH_STATE_MONITOR, true, false);
            }
            else
            {
                MeshWarning("Incorrect Mesh State value in syscfg, setting to Full\n");
                Mesh_SetMeshState(MESH_STATE_FULL, true, true);
            }
        }
    }

    // Set Mesh enabled
    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr, out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg get mesh_enable failed Retrying 5 times\n");
        for(i=0; i<5; i++)
        {
          if(!Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr, out_val, sizeof(out_val)))
          {
              MeshInfo("Syscfg get passed in %d retrial\n", i+1);
              t2_event_d("SYS_INFO_SYSCFG_get_passed",  1);
              rc = strcmp_s("true",strlen("true"),out_val,&ind);
              ERR_CHK(rc);
              if((ind == 0 ) && (rc == EOK))
              {
                  Mesh_SetEnabled(true, true);
              }
              else
              {
                  rc = strcmp_s("false",strlen("false"),out_val,&ind);
                  ERR_CHK(rc);
                  if((ind == 0 ) && (rc == EOK))
                  {
                     MeshInfo("Setting initial mesh wifi to disabled\n");
                     Mesh_SetEnabled(false, true);
                  }
                  else
                      Mesh_Recovery();
              }
              break;
          }
          else
           MeshInfo("Syscfg get failed in %d retrial\n", i+1);
        }
        if(i==5) {
         MeshInfo("All retrial failed for syscfg get , try reading from syscfg.db before applying default\n");
         t2_event_d("SYS_ERROR_SyscfgGet_retry_failed", 1);
         cmd=popen("grep \"mesh_enable\" /nvram/syscfg.db | cut -d \"=\" -f2","r"); 
         if (cmd==NULL) {
             cmd=popen("grep \"mesh_enable\" /opt/secure/data/syscfg.db | cut -d \"=\" -f2","r"); 
             if(cmd==NULL) {
                MeshInfo("Error opening syscfg.db file, do final attempt for recovery\n");
         	t2_event_d("SYS_ERROR_SYSCFG_Open_failed", 1);
                Mesh_Recovery();
             }
        }
        else
        {
           fgets(mesh_enable, sizeof(mesh_enable), cmd);
           MeshInfo("Manual Reading from db file = %s\n",mesh_enable);
           rc = strcmp_s("true",strlen("true"),mesh_enable,&ind);
           ERR_CHK(rc);
           rc1 = strcmp_s("false",strlen("false"),mesh_enable,&ind1);
           ERR_CHK(rc1);
           if(((ind ==0 ) && (rc == EOK)) || ((ind1 == 0) && (rc1 == EOK)))
               Mesh_SetEnabled(mesh_enable, true);
           else
           {
               MeshInfo("mesh_enable returned null from syscfg.db final attempt for recovery\n");
               t2_event_d("SYS_ERROR_ApplyDefaut_MeshStatus", 1);
               Mesh_Recovery();
           }
           pclose(cmd);
         }
       }
    } else {
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK)){
            Mesh_SetEnabled(true, true);
        }
        else {
            rc = strcmp_s("false",strlen("false"),out_val,&ind);
            ERR_CHK(rc); 
            if((ind == 0) && (rc == EOK)){
                MeshInfo("Setting initial mesh wifi default to disabled\n");
               Mesh_SetEnabled(false, true);
            }
            else {
            MeshInfo("Unexpected value from syscfg , doing recovery\n");
            Mesh_Recovery();
           }
       }  
    }
   
    out_val[0]='\0'; 
    if(Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_RFC_UPDATE].sysStr, out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg error, Setting Ethbhaul mode to default FALSE\n");
        Mesh_SetMeshEthBhaul(false,true);
    }
    else
    {
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((ind ==0 ) && (rc == EOK))
        {
           MeshInfo("Setting initial ethbhaul mode to true\n");
           Mesh_SetMeshEthBhaul(true,true);
        }
        else
        {
           rc = strcmp_s("false",strlen("false"),out_val,&ind);
           ERR_CHK(rc);
           if((ind ==0 ) && (rc == EOK))
           {
               MeshInfo("Setting initial ethbhaul mode to false\n");
               Mesh_SetMeshEthBhaul(false,true);
           }
           else
           {
               MeshInfo("Ethernet Bhaul status error from syscfg , setting default FALSE\n");
               Mesh_SetMeshEthBhaul(false,true);
           }
        }
    }

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr("mesh_ovs_enable", out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg error, Setting OVS mode to default\n");
        Mesh_SetOVS(false,true);
    }
    else
    {
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK))
        {
           MeshInfo("Setting initial OVS mode to true\n");
           Mesh_SetOVS(true,true);
        }
        else
        {
           rc = strcmp_s("false",strlen("false"),out_val,&ind);
           ERR_CHK(rc);
           if((ind == 0) && (rc == EOK))
           {
               MeshInfo("Setting initial OVS mode to false\n");
               Mesh_SetOVS(false,true);
           }
           else
           {
              MeshInfo("OVS status error from syscfg , setting default\n");
              Mesh_SetOVS(false,true);
           }
         }
     }

     out_val[0]='\0';
     if(Mesh_SysCfgGetStr("mesh_gre_acc_enable", out_val, sizeof(out_val)) != 0)
     {
             MeshInfo("Syscfg error, Setting gre acc mode to default\n");
             Mesh_SetGreAcc(false,true);
     } else {
          if (strncmp(out_val, "true", 4) == 0) {
               MeshInfo("Setting initial gre acc mode to true\n");
               Mesh_SetGreAcc(true,true);
          } else if (strncmp(out_val, "false", 5) == 0) {
               MeshInfo("Setting initial gre acc mode to false\n");
               Mesh_SetGreAcc(false,true);
          } else {
               MeshInfo("gre acc status error from syscfg , setting default\n");
               Mesh_SetGreAcc(false,true);
          }
     }
    // MeshInfo("Exiting from %s\n",__FUNCTION__);
}


/**
 * @brief Mesh Agent Update Connected Device
 *
 * This function will update the connected device table and notify
 * Mesh of changes
 */
bool Mesh_UpdateConnectedDevice(char *mac, char *iface, char *host, char *status)
{
    // send out notification to plume
    MeshSync mMsg = {0};
    errno_t rc[2] = {-1, -1};
    int ind[2] = {-1, -1};

    // Notify plume
    // Set sync message type
    if( Mesh_PodAddress(mac, FALSE)) {
     MeshInfo("Skipping pod connect event to plume cloud | mac=%s\n", mac);
     return false;
    }
    mMsg.msgType = MESH_CLIENT_CONNECT;
    if (mac != NULL && mac[0] != '\0') {
        rc[0] = strcpy_s(mMsg.data.meshConnect.mac, sizeof(mMsg.data.meshConnect.mac), mac);
        if(rc[0] != EOK)
        {
            ERR_CHK(rc[0]);
            MeshError("Error in copying mac to Connected Client\n");
            return false;
        }
    } else {
        MeshWarning("Mac address is NULL in connected client message, ignoring\n");
        return false;
    }

    if (status != NULL && status[0] != '\0') {
        rc[0] = strcmp_s("Connected",strlen("Connected"),status,&ind[0]);
        ERR_CHK(rc[0]);
        rc[1] = strcmp_s("Online",strlen("Online"),status,&ind[1]);
        ERR_CHK(rc[1]);
        mMsg.data.meshConnect.isConnected = ((((ind[0] == 0) && (rc[0] == EOK)) || ((ind[1] == 0) && (rc[1] == EOK)))? true:false);
    } else {
        MeshWarning("Connect status is NULL in connected client message, ignoring\n");
        return false;
    }

    if (iface != NULL && iface[0] != '\0') {
        mMsg.data.meshConnect.iface = Mesh_IfaceLookup(iface);
    } else {
        MeshWarning("Interface is NULL in connected client message, ignoring\n");
        return false;
    }

    if (host != NULL && host[0] != '\0') {
        rc[0] = strcpy_s(mMsg.data.meshConnect.host, sizeof(mMsg.data.meshConnect.host), host);
        if(rc[0] != EOK)
        {
            ERR_CHK(rc[0]);
            MeshError("Error in copying host to connected client\n");
            return false;
        }
    }
    // update our connected device table
    Mesh_UpdateClientTable(mMsg.data.meshConnect.iface, mMsg.data.meshConnect.mac, mMsg.data.meshConnect.host, mMsg.data.meshConnect.isConnected);

    // We filled our data structure so we can send it off
    msgQSend(&mMsg);

    return true;
}

/**
 * @brief Mesh Agent Send RFC parameter to plume managers
 *
 * This function will notify plume agent about RFC changes
 */ 
void Mesh_sendRFCUpdate(const char *param, const char *val, eRfcType type)
{   
    // send out notification to plume
    MeshSync mMsg = {0};
    errno_t rc = -1;
    // Notify plume
    // Set sync message type
    mMsg.msgType = MESH_RFC_UPDATE;
    rc = strcpy_s(mMsg.data.rfcUpdate.paramname, sizeof(mMsg.data.rfcUpdate.paramname),  param);
    if(rc != EOK)
    {
        ERR_CHK(rc);
        MeshError("Error in copying paramname for RFC Update\n");
        return;
    }
    rc = strcpy_s(mMsg.data.rfcUpdate.paramval, sizeof(mMsg.data.rfcUpdate.paramval), val);
    if(rc != EOK)
    {
        ERR_CHK(rc);
        MeshError("Error in copying paramval for RFC Update\n");
        return;
    }
    mMsg.data.rfcUpdate.type = type;
    MeshInfo("RFC_UPDATE: param: %s val:%s type=%d\n",mMsg.data.rfcUpdate.paramname, mMsg.data.rfcUpdate.paramval, mMsg.data.rfcUpdate.type);
    msgQSend(&mMsg);
    return true;
} 

/**
 * @brief Mesh Agent Sync DHCP lease
 *
 * This function will notify plume agent to process the dnsmasq.lease
 * file 
 */
void Mesh_sendDhcpLeaseSync(void)
{
    // send out notification to plume
    MeshSync mMsg = {0};
    //Setting the MSB of clientSocketsMask as state m/c to make sure we dont send any dnsmasq lease updates to 
    //plume while dnsmasq.lease sync is happening
    clientSocketsMask |= (1 << MAX_CONNECTED_CLIENTS); 
    //copy the dnsmasq.leases file from ARM to Atom and send out SYNC message to use the file
    MeshInfo("Copying dnsmasq.leases file from ARM to Atom for the first time\n");
    system("/usr/ccsp/wifi/synclease.sh");
#if 1

    // Notify plume
    // Set sync message type
    MeshInfo("Sending Mesh sync lease notification to plume agent\n");
    mMsg.msgType = MESH_DHCP_RESYNC_LEASES;
    msgQSend(&mMsg);
    //Prash: umask the MSB so that , we can go ahead sending dnsmasq lease notifications
    clientSocketsMask &= ~(1 << MAX_CONNECTED_CLIENTS); 
#endif
    return true;
}

/**
 * @brief Mesh Agent Sync DHCP lease
 *
 * This function will notify plume agent if any change in the
 * lease 
 */
void Mesh_sendDhcpLeaseUpdate(int msgType, char *mac, char *ipaddr, char *hostname, char *fingerprint)
{
    // send out notification to plume
    MeshSync mMsg = {0};
    errno_t rc = -1;
    // Notify plume
    // Set sync message type
    mMsg.msgType = msgType;
    if(clientSocketsMask && msgType <= MESH_DHCP_UPDATE_LEASE)
    {
       rc = strcpy_s(mMsg.data.meshLease.mac, sizeof(mMsg.data.meshLease.mac), mac);
       if(rc != EOK)
       {
           ERR_CHK(rc);
           MeshError("Error in copying mac address for DHCP lease update, mac - %s\n", mac);
           return;
       }
       rc = strcpy_s(mMsg.data.meshLease.ipaddr, sizeof(mMsg.data.meshLease.ipaddr), ipaddr);
       if(rc !=EOK)
       {
          ERR_CHK(rc);
          MeshError("Error in copying ip address for DHCP lease update, mac - %s\n", mac);
          return;
       }
       rc = strcpy_s(mMsg.data.meshLease.hostname, sizeof(mMsg.data.meshLease.hostname), hostname);
       if(rc !=EOK)
       {
           ERR_CHK(rc);
           MeshError("Error in copying hostname for DHCP lease update, mac - %s\n", mac);
           return;
       }
       rc = strcpy_s(mMsg.data.meshLease.fingerprint, sizeof(mMsg.data.meshLease.fingerprint), fingerprint);
       if(rc !=EOK)
       {
           ERR_CHK(rc);
           MeshError("Error in copying fingerprint for DHCP lease update, mac - %s\n", mac);
           return;
       }
       MeshInfo("DNSMASQ: %d %s %s %s %s\n",mMsg.msgType,mMsg.data.meshLease.mac, mMsg.data.meshLease.ipaddr, mMsg.data.meshLease.hostname, mMsg.data.meshLease.fingerprint);
       msgQSend(&mMsg);
       // Link change notification: prints telemetry on pod networks
       if( msgType != MESH_DHCP_REMOVE_LEASE && Mesh_PodAddress(mac, FALSE) && strstr( ipaddr, POD_IP_PREFIX)) {
          Mesh_logLinkChange();
       }

    }
    return true;
}

/**
 * @brief Mesh Agent register system events
 *
 * This function will register the sysevents.
 *
 */
static bool Mesh_Register_sysevent(ANSC_HANDLE hThisObject)
{
    bool status = false;
    const int max_retries = 6;
    int retry = 0;
    // MeshInfo("Entering into %s\n",__FUNCTION__);

    // Initialize syscfg
    syscfg_init();

    do
    {
        sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "meshAgent", &sysevent_token);
        if (sysevent_fd < 0)
        {
            MeshError("meshAgent failed to register with sysevent daemon\n");
            status = false;
        }
        else
        {
            MeshInfo("meshAgent registered with sysevent daemon successfully\n");
            status = true;
        }

        //Make another connection for gets/sets
        sysevent_fd_gs = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "meshAgent-gs", &sysevent_token_gs);
        if (sysevent_fd_gs < 0)
        {
            MeshError("meshAgent-gs failed to register with sysevent daemon\n");
            status = false;
        }
        else
        {
            MeshInfo("meshAgent-gs registered with sysevent daemon successfully\n");
            status = true;
        }

        if(status == false) {
            system("/usr/bin/syseventd");
                sleep(5);
        }
    }while((status == false) && (retry++ < max_retries));


    if (status != false)
       Mesh_SetDefaults(hThisObject);

    // MeshInfo("Exiting from %s\n",__FUNCTION__);
    return status;
}


/**************************************************************************/
/*! \fn void *Mesh_sysevent_handler(void *data)
 **************************************************************************
 *  \brief Function to process sysevent event
 *  \return 0
**************************************************************************/
static void *Mesh_sysevent_handler(void *data)
{
    // MeshInfo("Entering into %s\n",__FUNCTION__);

    async_id_t wifi_init_asyncid;
    async_id_t wifi_ssidName_asyncid;
    async_id_t wifi_ssidAdvert_asyncid;
    async_id_t wifi_radio_channel_asyncid;
    async_id_t wifi_radio_channel_mode_asyncid;
    async_id_t wifi_apSecurity_asyncid;
    async_id_t wifi_apKickDevice_asyncid;
    async_id_t wifi_apKickAllDevice_asyncid;
    async_id_t wifi_apAddDevice_asyncid;
    async_id_t wifi_apDelDevice_asyncid;
    async_id_t wifi_macAddrControl_asyncid;
    async_id_t subnet_cfg_asyncid;
    async_id_t mesh_status_asyncid;
    async_id_t mesh_enable_asyncid;
    async_id_t mesh_url_asyncid;
    async_id_t wifi_txRate_asyncid;

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_RESET].sysStr,                     TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_RESET].sysStr,                     &wifi_init_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_SSID_NAME].sysStr,                 TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_SSID_NAME].sysStr,                 &wifi_ssidName_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_SSID_ADVERTISE].sysStr,            TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_SSID_ADVERTISE].sysStr,            &wifi_ssidAdvert_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_RADIO_CHANNEL_MODE].sysStr,        TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_RADIO_CHANNEL_MODE].sysStr,        &wifi_radio_channel_mode_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_RADIO_CHANNEL].sysStr,             TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_RADIO_CHANNEL].sysStr,             &wifi_radio_channel_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_SECURITY].sysStr,               TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_SECURITY].sysStr,               &wifi_apSecurity_asyncid);

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_KICK_ASSOC_DEVICE].sysStr,      TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_KICK_ASSOC_DEVICE].sysStr,      &wifi_apKickDevice_asyncid);

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES].sysStr, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES].sysStr, &wifi_apKickAllDevice_asyncid);

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_ADD_ACL_DEVICE].sysStr,         TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_ADD_ACL_DEVICE].sysStr,         &wifi_apAddDevice_asyncid);

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_DEL_ACL_DEVICE].sysStr,         TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_DEL_ACL_DEVICE].sysStr,         &wifi_apDelDevice_asyncid);

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_MAC_ADDR_CONTROL_MODE].sysStr,     TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_MAC_ADDR_CONTROL_MODE].sysStr,     &wifi_macAddrControl_asyncid);

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_SUBNET_CHANGE].sysStr,                  TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_SUBNET_CHANGE].sysStr,                  &subnet_cfg_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_STATUS].sysStr,                  TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_STATUS].sysStr,                  &mesh_status_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr,                  TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr,                  &mesh_enable_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_URL_CHANGE].sysStr,                   TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_URL_CHANGE].sysStr,                   &mesh_url_asyncid);

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_TXRATE].sysStr,                   TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_TXRATE].sysStr,                   &wifi_txRate_asyncid);


    for (;;)
    {
        unsigned char name[64], val[256];
        int namelen = sizeof(name);
        int vallen  = sizeof(val);
        int err;
        async_id_t getnotification_asyncid;
        errno_t rc       = -1;
        int     ind      = -1;

        // Tell the socket code we are ready to handle messages
        if (!s_SysEventHandler_ready) {
            s_SysEventHandler_ready = true;
        }

        err = sysevent_getnotification(sysevent_fd, sysevent_token, name, &namelen,  val, &vallen, &getnotification_asyncid);

        if (err)
        {
        	// this is actually a catastrophic error, but we are going to kill some time here
        	// hoping that selfheal will re-start the syseventd process and we can recover.
            MeshError("sysevent_getnotification failed with error: %d\n", err);
            sleep(120);
        }
        else
        {
            eMeshSyncType ret_val;
            if(Get_MeshSyncType(name,&ret_val))
            {
                if (ret_val == MESH_WIFI_RESET)
                {
                     if( val)
                         MeshInfo("received notification event %s val =%s \n", name, val);
                     else
                         MeshInfo("received notification event %s\n", name);
                         // Need to restart the meshwifi service if it is currently running.
                         if (g_pMeshAgent->meshEnable || svcagt_get_service_state(meshServiceName))
                         {
                              MeshSync mMsg = {0};

                              // Set sync message type
                              mMsg.msgType = MESH_WIFI_RESET;
                              mMsg.data.wifiReset.reset = true;

                              // We filled our data structure so we can send it off
                              msgQSend(&mMsg);

                              /**
                               * At this time, we are just restarting the mesh components when a wifi_init comes
                               * in. At some point in the future, they may handle the wifi_init directly rather
                               * than having to be re-started.
                               */
                              // shutdown
                              if (val && val[0] != '\0' && g_pMeshAgent->meshEnable)
                              {
                                  rc = strcmp_s("start", strlen("start"), val, &ind);
                                  if((rc == EOK) && (!ind))
                                  {
                                       MeshInfo("Stopping meshwifi service\n");
                                       svcagt_set_service_state(meshServiceName, false);
                                  }
                                  else
                                  {
                                       rc = strcmp_s("stop", strlen("stop"), val, &ind);
                                       if((rc == EOK) && (!ind))
                                       {
                                            MeshInfo("Starting meshwifi service\n");
                                            svcagt_set_service_state(meshServiceName, true);
                                       }
                                       else
                                            MeshWarning("Unsupported option %s \n", val);
                                  }
                               }
                            }
                            else {
                                   MeshInfo("meshwifi.service is not running - not restarting\n");
                            }
            }
            else if (ret_val == MESH_WIFI_RADIO_CHANNEL)
            {
                // Radio config sysevents will be formatted: ORIG|index|channel
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_RADIO_CHANNEL;

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiRadioChannel.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("channel=%s\n", token);
                            mMsg.data.wifiRadioChannel.channel = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_RADIO_CHANNEL_MODE)
            {
                // Radio config sysevents will be formatted: ORIG|index|channel
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_RADIO_CHANNEL_MODE;

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiRadioChannelMode.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("channeModel=%s\n", token);
                            rc = strcpy_s(mMsg.data.wifiRadioChannelMode.channelMode, sizeof(mMsg.data.wifiRadioChannelMode.channelMode), token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying channel mode in MESH_WIFI_RADIO_CHANNEL_MODE\n");
                            }
                            else
                            {
                                valFound = true;
                            }
                            break;
                        case 3:
                            MeshInfo("gOnlyFlag=%s\n", token);
                            rc = strcmp_s("true",strlen("true"),token,&ind);
                            ERR_CHK(rc);
                            (mMsg.data.wifiRadioChannelMode.gOnlyFlag = ((ind == 0) && (rc == EOK)) ? 1:0);
                            valFound = true;
                            break;
                        case 4:
                            MeshInfo("nOnlyFlag=%s\n", token);
                            rc = strcmp_s("true",strlen("true"),token,&ind);
                            ERR_CHK(rc);
                            (mMsg.data.wifiRadioChannelMode.nOnlyFlag = ((ind == 0) && (rc == EOK)) ? 1:0);
                            valFound = true;
                            break;
                        case 5:
                            MeshInfo("acOnlyFlag=%s\n", token);
                            rc = strcmp_s("true",strlen("true"),token,&ind);
                            ERR_CHK(rc);
                            (mMsg.data.wifiRadioChannelMode.acOnlyFlag = ((ind == 0) && (rc == EOK)) ? 1:0);
                            valFound = true;
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_SSID_ADVERTISE)
            {
                // SSID config sysevents will be formatted: ORIG|index|ssid
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_SSID_ADVERTISE;

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiSSIDAdvertise.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("enable=%s\n", token);
                            rc = strcmp_s("true",strlen("true"),token,&ind);
                            ERR_CHK(rc);
                            (mMsg.data.wifiSSIDAdvertise.enable = ((ind == 0) && (rc == EOK)) ? 1:0);
                            valFound = true;
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_SSID_NAME)
            {
                // SSID config sysevents will be formatted: ORIG|index|ssid
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_SSID_NAME;

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiSSIDName.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            /*Coverity Fix CID:57710 PW.TOO_MANY_PRINTF_ARGS */
                            MeshInfo("ssid reveived:\n");
                            rc = strcpy_s(mMsg.data.wifiSSIDName.ssid, sizeof(mMsg.data.wifiSSIDName.ssid), token);
                            if(rc != EOK)
                            {
                                  ERR_CHK(rc);
                                  MeshError("Error in copying WiFI ssid\n");
                            }
                            else{
                                 valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_AP_SECURITY)
            {
                // AP config sysevents will be formatted: ORIG|index|passphrase|secMode|encryptMode
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token=NULL;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_AP_SECURITY;

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                           
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiAPSecurity.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                             /* Coverity Issue Fix - CID:125245 : Printf Args */
                            MeshInfo("passphrase recieved \n");
                            rc = strcpy_s(mMsg.data.wifiAPSecurity.passphrase, sizeof(mMsg.data.wifiAPSecurity.passphrase), token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying passphrase\n");
                            }
                            else{
                                valFound = true;
                            }
                            break;
                        case 3:
                             /* Coverity Issue Fix - CID:125245 : Printf Args*/
                            MeshInfo("security mode received\n");
                            rc = strcpy_s(mMsg.data.wifiAPSecurity.secMode, sizeof(mMsg.data.wifiAPSecurity.secMode), token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying security mode\n");
                            }
                            else{
                                valFound = true;
                            }
                            break;
                        case 4:
                             /* Coverity Issue Fix - CID:125245  : Printf Args*/
                            MeshInfo("encryption mode recieved\n");
                            rc = strcpy_s(mMsg.data.wifiAPSecurity.encryptMode, sizeof(mMsg.data.wifiAPSecurity.encryptMode), token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying encryption mode\n");
                            }
                            else{
                                valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_AP_KICK_ASSOC_DEVICE)
            {
                // AP config sysevents will be formatted: ORIG|index|passphrase|secMode|encryptMode
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_AP_KICK_ASSOC_DEVICE;

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiAPKickAssocDevice.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("mac=%s\n", token);
                            rc = strcpy_s(mMsg.data.wifiAPKickAssocDevice.mac, sizeof(mMsg.data.wifiAPKickAssocDevice.mac), token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying mac address - MESH_WIFI_AP_KICK_ASSOC_DEVICE\n");
                            }
                            else{
                                valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES)
            {
                // AP config sysevents will be formatted: ORIG|index|passphrase|secMode|encryptMode
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES;

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiAPKickAllAssocDevices.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_AP_ADD_ACL_DEVICE)
            {
                // AP config sysevents will be formatted: ORIG|index|passphrase|secMode|encryptMode
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_AP_ADD_ACL_DEVICE;

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiAPAddAclDevice.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("mac=%s\n", token);
                            rc = strcpy_s(mMsg.data.wifiAPAddAclDevice.mac, sizeof(mMsg.data.wifiAPAddAclDevice.mac), token);
                            if(rc != EOK)
                            {
                                  ERR_CHK(rc);
                                  MeshError("Error in copying mac address - MESH_WIFI_AP_ADD_ACL_DEVICE\n");
                            }
                            else{
                                  valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_AP_DEL_ACL_DEVICE)
            {
                // AP config sysevents will be formatted: ORIG|index|passphrase|secMode|encryptMode
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_AP_DEL_ACL_DEVICE;

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiAPDelAclDevice.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("mac=%s\n", token);
                            rc = strcpy_s(mMsg.data.wifiAPDelAclDevice.mac, sizeof(mMsg.data.wifiAPDelAclDevice.mac), token);
                            if(rc != EOK)
                            {
                                 ERR_CHK(rc);
                                 MeshError("Error in copying mac address - MESH_WIFI_AP_DEL_ACL_DEVICE\n");
                            }
                            else{
                                valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_MAC_ADDR_CONTROL_MODE)
            {
                // AP config sysevents will be formatted: ORIG|index|passphrase|secMode|encryptMode
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_MAC_ADDR_CONTROL_MODE;

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiAPKickAssocDevice.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("isEnabled=%s\n", token);
                            rc = strcmp_s("true",strlen("true"),token,&ind);
                            ERR_CHK(rc);
                            (mMsg.data.wifiMacAddrControlMode.isEnabled = ((ind == 0) && (rc == EOK)) ? 1:0);
                            valFound = true;
                            break;
                        case 3:
                            MeshInfo("isBlacklist=%s\n", token);
                            rc = strcmp_s("true",strlen("true"),token,&ind);
                            ERR_CHK(rc);
                            (mMsg.data.wifiMacAddrControlMode.isBlacklist = ((ind == 0) && (rc == EOK)) ? 1:0);
                            valFound = true;
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_STATUS)
            {
                // mesh sysevents will be formatted: ORIG|mode
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    char url[128] = {0};
                    eMeshWifiStatusType status = MESH_WIFI_STATUS_OFF;

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process MESH status sysevent messages
                            rc = strcmp_s("MESH", strlen("MESH"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("mesh_status=%s\n", token);
                            rc = strcmp_s("Init", strlen("Init"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind == 0) && (rc == EOK)) {
				t2_event_d("WIFI_INFO_MeshInit", 1);
  			    }
                            status = Mesh_WifiStatusLookup(token);
                            valFound = true;
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound && (status == MESH_WIFI_STATUS_FULL || status == MESH_WIFI_STATUS_MONITOR)) {
                        // Mesh Full
                        // Ok, if Plume told us that they are in full mode, we should send them the list of connected devices
                        ClientTableIter iter;
                        /* Coverity Issue Fix - CID:72175 : UnInitialised Variable*/
                        eMeshIfaceType iface = MESH_IFACE_NONE;
                        char *mac;
                        char *host;

	 		MeshInfo("Update the active client list from host table\n");
			Mesh_InitClientList();

                        MeshInfo("Mesh is in Full/Monitor Mode, report %d connected clients\n", Mesh_ActiveClientCount());

                        Mesh_ClientTableIterInit(&iter);
                        while (Mesh_ClientTableIterNext(&iter, &iface, &mac, &host))
                        {
                            // send out notification to plume
                           if( !Mesh_PodAddress(mac, FALSE)) 
                           {
                            MeshSync mMsg = {0};

                            // Notify plume
                            // Set sync message type
                            mMsg.msgType = MESH_CLIENT_CONNECT;
                            rc = strcpy_s(mMsg.data.meshConnect.mac, sizeof(mMsg.data.meshConnect.mac), mac);
                            if(rc != EOK)
                            {
                                  ERR_CHK(rc);
                                  MeshError("Error in copying mac in MESH_CLIENT_CONNECT\n");
                                  return;
                            }
                            mMsg.data.meshConnect.isConnected = true; // all reported devices are "connected"
                            mMsg.data.meshConnect.iface = iface;
                            if (host != NULL &&  host[0] != '\0') {
                                rc = strcpy_s(mMsg.data.meshConnect.host, sizeof(mMsg.data.meshConnect.host),host);
                                if(rc != EOK)
                                {
                                     ERR_CHK(rc);
                                     MeshError("Error in copying host in MESH_CLIENT_CONNECT\n");
                                     return;
                                }
                            }

                            // We filled our data structure so we can send it off
                            msgQSend(&mMsg);
                           }
                        }
                    }
                }
            }
            else if (ret_val == MESH_WIFI_ENABLE)
            {
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    char url[128] = {0};
                    bool enabled = false;

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("mesh_enable=%s\n", token);
                            rc = strcmp_s("true", strlen("true"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind == 0) && (rc == EOK))
                            {
                                enabled = true;
                            }
                            valFound = true;
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound) {
                        if(enabled==true)
                        {
                            if(is_bridge_mode_enabled())// || is_band_steering_enabled() || is_DCS_enabled())
                            {
                                enabled = false;
                            }
                        }
                        // We filled our data structure so we can send it off
                        Mesh_SetEnabled(enabled, false);
                    }
                }
            }
            else if (ret_val == MESH_URL_CHANGE)
            {
                // mesh url changed
                // Url config sysevents will be formatted: ORIG|url
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    char url[128] = {0};

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("url=%s\n", token);
                            rc = strcpy_s(url, sizeof(url),token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying url in MESH_URL_CHANGE\n");
                            }
                            else{
                                valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        Mesh_SetUrl(url, false);
                    }
                }
            }
            else if (ret_val == MESH_SUBNET_CHANGE)
            {
                // mesh subnet change changed
                // Subnet change config sysevents will be formatted: ORIG|gwIP|netmask
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_SUBNET_CHANGE;

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("gwIP=%s\n", token);
                            rc = strcpy_s(mMsg.data.subnet.gwIP, sizeof(mMsg.data.subnet.gwIP),token);
                            if(rc != EOK)
                            {
                                 ERR_CHK(rc);
                                 MeshError("Error in copying gwIP in MESH_SUBNET_CHANGE\n");
                            }
                            else{
                                 valFound = true;
                            }
                            break;
                        case 2:
                            MeshInfo("netmask=%s\n", token);
                            rc = strcpy_s(mMsg.data.subnet.netmask, sizeof(mMsg.data.subnet.netmask),token);
                            if(rc != EOK)
                            {
                                 ERR_CHK(rc);
                                 MeshError("Error in copying netmask in MESH_SUBNET_CHANGE\n");
                            }
                            else{
                                 valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_TXRATE)
            {
                // TxRate config sysevents will be formatted: ORIG|index|BasicRates:<basicRates>|OperationalRates:<operationalRates>
                if (val && val[0] != '\0')
                {
                    const char delim[2] = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_TXRATE;

                    // grab the first token
                    token = strtok(val, delim);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiTxRate.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                        {
                            // We need to strip off the qualifier "BasicRates:" from the front of the string
                            char *strPtr = strchr(token, ':');

                            if (strPtr != NULL) {
                                MeshInfo("basicRates=%s\n", (strPtr+1));
                                rc = strcpy_s(mMsg.data.wifiTxRate.basicRates, sizeof(mMsg.data.wifiTxRate.basicRates), (strPtr+1));
                                if(rc != EOK)
                                {
                                     ERR_CHK(rc);
                                     MeshError("Error in copying WiFi basicRates in MESH_WIFI_TXRATE\n");
                                }
                            } else {
                                // we couldn't find our qualifier, just copy the whole thing
                                MeshInfo("basicRates=%s\n", token);
                                rc = strcpy_s(mMsg.data.wifiTxRate.basicRates, sizeof(mMsg.data.wifiTxRate.basicRates), token);
                                if(rc != EOK)
                                {
                                     ERR_CHK(rc);
                                     MeshError("Error in copying Whole qualifier WiFi basicRates in MESH_WIFI_TXRATE\n");
                                }
                            }
                            if(rc == EOK)
                            {
                                  valFound = true;
                            }
                        }
                            break;
                        case 3:
                        {
                            // We need to strip off the qualifier "OperationalRates:" from the front of the string
                            char *strPtr = strchr(token, ':');

                            if (strPtr != NULL) {
                                MeshInfo("operationalRates=%s\n", (strPtr+1));
                                rc = strcpy_s(mMsg.data.wifiTxRate.opRates, sizeof(mMsg.data.wifiTxRate.opRates), (strPtr+1));
                                if(rc != EOK)
                                {
                                    ERR_CHK(rc);
                                    MeshError("Error in copying WiFi opRates in MESH_WIFI_TXRATE\n");
                                } 
                            } else {
                                // we couldn't find our qualifier, just copy the whole thing
                                MeshInfo("operationalRates=%s\n", token);
                                rc = strcpy_s(mMsg.data.wifiTxRate.opRates, sizeof(mMsg.data.wifiTxRate.opRates), token);
                                if(rc != EOK)
                                {
                                    ERR_CHK(rc);
                                    MeshError("Error in copying Whole qualifier WiFi opRates in MESH_WIFI_TXRATE\n");
                                }
                            }
                            if(rc == EOK)
                            {
                                 valFound = true;
                            }
                        }
                            break;
                        default:
                            break;

                        }
                        token = strtok(NULL, delim);
                        idx++;
                    }

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else
            {
                MeshWarning("undefined event %s \n",name);
            }
          }
        }
    }

    // MeshInfo("Exiting from %s\n",__FUNCTION__);
}

/**
 * @brief Mesh Agent initialize client connection list
 *
 * Initialize the client list table with the devices connected before mesh was started.
 */

void Mesh_InitClientList()
{
    char val[256] = {0};
    errno_t rc = -1;

#ifdef MESH_DOWNLOADABLE_MODULE
    FILE *fp = popen("dmcli eRT getv Device.Hosts.Host. > /tmp/client_list.txt; /tmp/plume_dnld/usr/ccsp/mesh/active_host_filter.sh /tmp/client_list.txt", "r");
#else
    FILE *fp = popen("dmcli eRT getv Device.Hosts.Host. > /tmp/client_list.txt; /usr/ccsp/mesh/active_host_filter.sh /tmp/client_list.txt", "r");
#endif

    if ( fp != NULL) {
        while (fgets(val, sizeof(val), fp) != NULL)
        {
            char *token;
            int idx = 0;
            const char delim[3] = "|\n";
            char mac[MAX_MAC_ADDR_LEN] = {0};
            char host[MAX_HOSTNAME_LEN] = {0};
            eMeshIfaceType iface = MESH_IFACE_NONE;

            token = strtok(val, delim);
            while (token != NULL)
            {
                switch (idx) {
                case 0: // Mac Address
                    rc = strcpy_s(mac, sizeof(mac), token);
                    if(rc != EOK)
                    {
                        ERR_CHK(rc);
                        MeshError("MAC Address not added\n");
                        pclose(fp);
                        return;
                    }
                    break;
                case 1: // Interface
                    iface = Mesh_IfaceLookup(token);
                    break;
                case 2: // HostName
                    rc = strcpy_s(host, sizeof(host), token);
                    if(rc != EOK)
                    {
                        ERR_CHK(rc);
                        MeshError("MAC hostname not added\n");
                        pclose(fp);
                        return;
                    }
                    break;
                default:
                    break;
                }
                token = strtok(NULL, delim);
                idx++;
            }
            // all of the reported entries from the host filter are active
            Mesh_UpdateClientTable(iface, mac, host, true);
        }

        pclose(fp);
    }
}


/**
 *  @brief Mesh Agent Initialize code
 *
 *  This function will initialize the Mesh Agent and set up any data required.
 *
 *  @return 0
 */
int Mesh_Init(ANSC_HANDLE hThisObject)
{
    int status = 0;
    int thread_status = 0;
    char thread_name[THREAD_NAME_LEN] = { 0 };
    errno_t rc = -1;
    // MeshInfo("Entering into %s\n",__FUNCTION__);

    // Create our message server thread
    thread_status = pthread_create(&mq_server_tid, NULL, msgQServer, NULL);
    if (thread_status == 0)
    {
        MeshInfo("msgQServer thread created successfully\n");

        rc = strcpy_s(thread_name, sizeof(thread_name),  "Mesh_msgQServer");
        if(rc != EOK)
        {
           ERR_CHK(rc);
           MeshError("Error in setting Mesh_msgQServer thread_name\n");
        }

        if ((rc == EOK) && (pthread_setname_np(mq_server_tid, thread_name) == 0))
        {
            MeshInfo("msgQServer thread name %s set successfully\n", thread_name);
        }
        else
        {
            MeshError("%s error occurred while setting msgQServer thread name\n", strerror(errno));
        }
    }
    else
    {
        MeshError("%s error occurred while creating msgQServer thread\n", strerror(errno));
        status = -1;
    }


    if (Mesh_Register_sysevent(hThisObject) == false)
    {
        MeshError("Mesh_Register_sysevent failed\n");
        status = -1;
    }
    else
    {
        MeshInfo("Mesh_Register_sysevent Successful\n");

        thread_status = pthread_create(&sysevent_tid, NULL, Mesh_sysevent_handler, NULL);
        if (thread_status == 0)
        {
            MeshInfo("Mesh_sysevent_handler thread created successfully\n");

            rc = strcpy_s(thread_name, sizeof(thread_name), "Mesh_sysevent");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                MeshError("Error in setting Mesh_sysevent thread_name\n");
                return -1;
            }

            if (pthread_setname_np(sysevent_tid, thread_name) == 0)
            {
               MeshInfo("Mesh_sysevent_handler thread name %s set successfully\n", thread_name);
            }
            else
            {
                MeshError("%s error occurred while setting Mesh_sysevent_handler thread name\n", strerror(errno));
            }

            sleep(5);
        }
        else
        {
            MeshError("%s error occurred while creating Mesh_sysevent_handler thread\n", strerror(errno));
            status = -1;
        }
    }
    // Start a server for dnsmasq lease notification
    thread_status = 0;
    thread_status = pthread_create(&lease_server_tid, NULL, leaseServer, NULL);
    if (thread_status == 0)
    {
        MeshInfo("leaseServer thread created successfully\n");

        //memset( thread_name, '\0', sizeof(char) * THREAD_NAME_LEN );
        /* Coverity Issue Fix - CID:59861 DC.STRING_BUFFER  */
        rc = strcpy_s(thread_name, sizeof(thread_name), "MeshLeaseServer");
        if(rc != EOK)
        {
            ERR_CHK(rc);
            MeshError("Error in setting MeshLeaseServer thread_name\n");
            return -1;
        }

        if (pthread_setname_np(lease_server_tid, thread_name) == 0)
        {
            MeshInfo("leaseServer thread name %s set successfully\n", thread_name);
        }
        else
        {
            MeshError("%s error occurred while setting msgQServer thread name\n", strerror(errno));
        }
    }
    else
    {
        MeshError("%s error occurred while creating msgQServer thread\n", strerror(errno));
        status = -1;
    } 
    // Start message queue client thread (Communications to/from RDKB CcspWifiSsp)

    // MeshInfo("Exiting from %s\n",__FUNCTION__);
    return status;
}


ANSC_STATUS
CosaDmlMeshAgentInit
    (
        ANSC_HANDLE                 hThisObject
    )
{
    MeshInfo("Initialize MeshAgent \n");

    if (Mesh_Init(hThisObject) != 0)
    {
        MeshError("Mesh Agent Initialization failed\n");
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}


#endif
