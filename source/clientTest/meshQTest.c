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

#ifndef _RDKB_MESH_Q_TEST_C_
#define _RDKB_MESH_Q_TEST_C_

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
#include <limits.h>
#include "stdbool.h"
#include <pthread.h>

#include <fcntl.h>

#include "meshsync_msgs.h"
#include "safec_lib_common.h"

#if defined(ENABLE_MESH_SOCKETS)
/*
 * Unix Domain Sockets
 */
#include <sys/socket.h>
#include <sys/un.h>

const char meshSocketPath[] = MESH_SOCKET_PATH_NAME;
static int mq_socket; //socket descriptor

#else
/*
 * Message Queue setup values
 */
#include <mqueue.h>

const int QUEUE_PERMISSIONS=0660;
const int MAX_MESSAGES=10;  // max number of messages the can be in the queue

static mqd_t qd_server; // msg queue server handle
#endif

extern MeshSync_MsgItem meshSyncMsgArr[];
#define THREAD_NAME_LEN 16 //length is restricted to 16 characters, including the terminating null byte

static pthread_t mq_server_tid; // server thread id
static pthread_t mq_test_tid; // test loop thread id

static int bRunning;

// MeshSync Message structure.
typedef struct
{
    eMeshSyncType mType;       // Enum value of the mesh sync msg
    char         *msgStr;      // mesh sync message string
    char         *sysStr; // sysevent string
} MeshSync_MsgItem;

/**
 * Canned test messages to send to MeshAgent/RDKB
 */

MeshSync mWifiReset = {MESH_WIFI_RESET,.data={.wifiReset={1}}};
MeshSync mRadioChan = {MESH_WIFI_RADIO_CHANNEL,.data={.wifiRadioChannel={0,16}}};
MeshSync mRadioChanMode = {MESH_WIFI_RADIO_CHANNEL_MODE,
            .data={.wifiRadioChannelMode={0,"11ACVHT80",0,0,1}}};
MeshSync mSSIDName = {MESH_WIFI_SSID_NAME,.data={.wifiSSIDName={0,"skippy"}}};
MeshSync mSSIDAd = {MESH_WIFI_SSID_ADVERTISE,.data={.wifiSSIDAdvertise={0,1}}};
MeshSync mAPSec = {MESH_WIFI_AP_SECURITY,.data={.wifiAPSecurity={0,"passphrase","WPA-WPA2-Personal","AESEncryption"}}};
MeshSync mAPKick = {MESH_WIFI_AP_KICK_ASSOC_DEVICE,.data={.wifiAPKickAssocDevice={0,"0123456789AB"}}};
MeshSync mAPKickAll = {MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES,.data={.wifiAPKickAllAssocDevices={0}}};
MeshSync mAPAdd = {MESH_WIFI_AP_ADD_ACL_DEVICE,.data={.wifiAPAddAclDevice={0,"0123456789AB"}}};
MeshSync mAPDel = {MESH_WIFI_AP_DEL_ACL_DEVICE,.data={.wifiAPDelAclDevice={0,"0123456789AB"}}};
MeshSync mMACControl = {MESH_WIFI_MAC_ADDR_CONTROL_MODE,.data={.wifiMacAddrControlMode={0,1,1}}};
MeshSync mSubnet = {MESH_SUBNET_CHANGE,.data={.subnet={"192.168.0.1","255.255.255.0"}}};
MeshSync mUrl = {MESH_URL_CHANGE,.data={.url={"www.google.com"}}};
MeshSync mStatus = {MESH_WIFI_STATUS,.data={.wifiStatus={MESH_WIFI_STATUS_MONITOR}}};
MeshSync mEnable = {MESH_WIFI_ENABLE,.data={0}};

#if defined(ENABLE_MESH_SOCKETS)
/*
 * Client message queue (receive messages from MeshAgent/RDKB)
 */
static int msgQClient(void *data)
{
    struct sockaddr_un addr;
    MeshSync rxBuf;
    errno_t rc = -1;

    if ( (mq_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
      printf("socket error\n");
      return errno;
    }

    rc = memset_s(&addr, sizeof(addr), 0, sizeof(addr));
    ERR_CHK(rc);
    addr.sun_family = AF_UNIX;
    if (*meshSocketPath == '\0') {
      *addr.sun_path = '\0';
      rc = strcpy_s(addr.sun_path+1, sizeof(addr.sun_path)-1, meshSocketPath+1);
      if(rc != EOK)
      {
          ERR_CHK(rc);
          return rc;
      }
    } else {
      rc = strcpy_s(addr.sun_path, sizeof(addr.sun_path), meshSocketPath);
      if(rc != EOK)
      {
          ERR_CHK(rc);
          return rc;
      }
    }

    if (connect(mq_socket, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
      printf("connect error\n");
      return errno;
    }

    while (bRunning)
    {
        // grab any messages
        if (read(mq_socket, (void *) &rxBuf, sizeof(MeshSync)) < 0) {
            // perror ("Server: mq_receive");
            printf("Error %d receiving message from mesh socket\n", errno);
            break; // kick out of loop and clean up
        }

        // Parse out the messages and send the sysevents
        {
            // Check to see if this is a valid message
            if (rxBuf.msgType >= MESH_SYNC_MSG_TOTAL)
            {
               printf("Error unknown message type %d - skipping\n", rxBuf.msgType);
               continue;
            }

            printf("%s - %s message received.\n", __FUNCTION__, meshSyncMsgArr[rxBuf.msgType].msgStr);
            // Do something exciting with the message
        }
    }

    return 0;
}
#else
/*
 * Client message queue (receive messages from MeshAgent/RDKB)
 */
static int msgQClient(void *data)
{
    // Start message queue server (communications from MeshAgent/RDKB)
    struct mq_attr qAttr, qAttr_old;
    MeshSync rxBuf;

    unsigned int prio;
    qAttr.mq_flags = 0;
    qAttr.mq_maxmsg = MAX_MESSAGES;
    qAttr.mq_msgsize = sizeof(MeshSync);
    qAttr.mq_curmsgs = 0;
    if ((qd_server = mq_open (MESH_CLIENT_QUEUE_NAME, O_RDONLY | O_CREAT, QUEUE_PERMISSIONS, &qAttr)) == -1) {
        // perror ("Server: mq_open (server)");
        printf("Error %d creating client message queue %s\n", errno, MESH_CLIENT_QUEUE_NAME);
        return errno;
    }

    // Get the attributes for my server message queue
    mq_getattr (qd_server, &qAttr);
    printf("%d messages are currently in the server queue\n", qAttr.mq_curmsgs);
    // Eat any previous messages in the queue
    if (qAttr.mq_curmsgs != 0) {
      // First set the queue to not block any calls
      qAttr.mq_flags = O_NONBLOCK;
      mq_setattr (qd_server, &qAttr, &qAttr_old);
      // Now eat all of the messages
      while (mq_receive (qd_server, (char *) &rxBuf, sizeof(MeshSync), &prio) != -1)
        printf("Received a message with priority %d.\n", prio);
      // The call failed.  Make sure errno is EAGAIN
      if (errno != EAGAIN) {
        printf("Error %d reading messages from %s\n", errno, MESH_CLIENT_QUEUE_NAME);
        return errno;
      }
      // Now restore the attributes
      mq_setattr (qd_server, &qAttr_old, 0);
    }

    while (bRunning)
    {
        // get the oldest message with highest priority
        if (mq_receive (qd_server, (char *) &rxBuf, sizeof(MeshSync), NULL) == -1) {
            // perror ("Server: mq_receive");
            printf("Error %d receiving message from queue %s\n", errno, MESH_CLIENT_QUEUE_NAME);
            break; // kick out of loop and clean up
        }

        // Parse out the messages and send the sysevents
        {
            // Check to see if this is a valid message
            if (rxBuf.msgType >= MESH_SYNC_MSG_TOTAL)
            {
               printf("Error unknown message type %d - skipping\n", rxBuf.msgType);
               continue;
            }

            printf("%s - %s message received.\n", __FUNCTION__, meshSyncMsgArr[rxBuf.msgType].msgStr);
            // Do something exciting with the message
        }

    }

    return 0;
}
#endif

/**
 * Test loop for sending requests to MeshAgent/RDKB
 */
static int msgQTest(void *data)
{
    int i = 0;

#if defined(ENABLE_MESH_SOCKETS)
#else
    mqd_t qd_client;
    struct mq_attr attr;

    if ((qd_client = mq_open (MESH_SERVER_QUEUE_NAME, O_WRONLY)) == -1) {
        printf("Error %d connecting to meshAgent msgQueue %s\n", errno, MESH_SERVER_QUEUE_NAME);
        return errno;
    }

    // Get the attributes for the RDKB message queue
    mq_getattr (qd_client, &attr);
    printf("%d messages are currently in the meshAgent queue\n", attr.mq_curmsgs);
#endif

    // Loop here forever
    char temp_buf [10];

    printf("Please select a message to send to MeshAgent\n");
    for (i=0; i<MESH_SYNC_MSG_TOTAL;i++)
    {
        printf("%d - %s\n",i,meshSyncMsgArr[i].msgStr);
    }
    printf("%d - Redraw Menu\n", MESH_SYNC_MSG_TOTAL);
    printf("%d - Quit\n", MESH_SYNC_MSG_TOTAL+1);

    printf ("Selection : ");
    while (fgets (temp_buf, 10, stdin) && bRunning) {
        MeshSync *msg = NULL;
        errno = 0;

        // parse user response and send canned message to RDKB
        int val = strtol(temp_buf, NULL, 10);

        if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
                || (errno != 0 && val == 0) || (val > (MESH_SYNC_MSG_TOTAL+1))) {
            printf("strtol error %d", errno);
        } else {
            switch (val) {
            case MESH_WIFI_RESET:
                msg = &mWifiReset;
                break;
            case MESH_WIFI_RADIO_CHANNEL:
                msg = &mRadioChan;
                break;
            case MESH_WIFI_RADIO_CHANNEL_MODE:
                msg = &mRadioChanMode;
                break;
            case MESH_WIFI_SSID_NAME:
                msg = &mSSIDName;
                break;
            case MESH_WIFI_SSID_ADVERTISE:
                msg = &mSSIDAd;
                break;
            case MESH_WIFI_AP_SECURITY:
                msg = &mAPSec;
                break;
            case MESH_WIFI_AP_KICK_ASSOC_DEVICE:
                msg = &mAPKick;
                break;
            case MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES:
                msg = &mAPKickAll;
                break;
            case MESH_WIFI_AP_ADD_ACL_DEVICE:
                msg = &mAPAdd;
                break;
            case MESH_WIFI_AP_DEL_ACL_DEVICE:
                msg = &mAPDel;
                break;
            case MESH_WIFI_MAC_ADDR_CONTROL_MODE:
                msg = &mMACControl;
                break;
            case MESH_SUBNET_CHANGE:
                msg = &mSubnet;
                break;
            case MESH_URL_CHANGE:
                msg = &mUrl;
                break;
            case MESH_WIFI_STATUS:
                msg = &mStatus;
                break;
            case MESH_WIFI_ENABLE:
                msg = &mEnable;
                break;
            case MESH_SYNC_MSG_TOTAL:
            {
                printf("Please select a message to send to MeshAgent\n");
                for (i=0; i<MESH_SYNC_MSG_TOTAL;i++)
                {
                    printf("%d - %s\n",i,meshSyncMsgArr[i].msgStr);
                }
                printf("%d - Redraw Menu\n", MESH_SYNC_MSG_TOTAL);
                printf("%d - Quit\n", MESH_SYNC_MSG_TOTAL+1);
                continue;
            }
                break;
            case (MESH_SYNC_MSG_TOTAL+1):
                    bRunning = false;
                    pthread_cancel(mq_server_tid); // kill the server thread
                break;
            default:
                break;
            }

            if (msg != NULL)
            {
                /* send the message */
                if (bRunning)
                {
                    printf("Sending %s to meshAgent/RDKB\n", meshSyncMsgArr[msg->msgType].msgStr);
#if defined(ENABLE_MESH_SOCKETS)
                    if (send(mq_socket, (void *) msg, sizeof(MeshSync), 0) == -1)
                    {
                        printf("Error %d sending connecting to meshAgent msgQueue socket %d\n",errno, mq_socket);
                        break;
                    }
#else
                    if (mq_send(qd_client, (char *) msg, sizeof(MeshSync), 0) == -1)
                    {
                        printf("Error %d sending connecting to meshAgent msgQueue %s\n",errno, MESH_SERVER_QUEUE_NAME);
                        break;
                    }
#endif
                    printf ("Selection: ");
                } else {
                    // The user wanted to quit, break out of fgets loop
                    break;
                }
            }
        }
    }

    return 0;
}

int Client_Init()
{
    int status = 0;
    int thread_status = 0;
    char thread_name[THREAD_NAME_LEN] = { 0 };
    errno_t rc = -1;

    bRunning = true;

    // Create our message server thread
    thread_status = pthread_create(&mq_server_tid, NULL, msgQClient, NULL);
    if (thread_status == 0)
    {
        printf("msgQClient thread created successfully\n");

        rc = strcpy_s( thread_name, sizeof(thread_name), "msgQClient");
        if(rc != EOK)
        {
            ERR_CHK(rc);
            return -1;
        }

        if (pthread_setname_np(mq_server_tid, thread_name) == 0)
        {
            printf("msgQClient thread name %s set successfully\n", thread_name);
        }
        else
        {
            printf("%s error occurred while setting msgQClient thread name\n", strerror(errno));
        }
    }
    else
    {
        printf("%s error occurred while creating msgQClient thread\n", strerror(errno));
        status = -1;
    }

    // Create our message Q test thread
    thread_status = pthread_create(&mq_test_tid, NULL, msgQTest, NULL);
    if (thread_status == 0)
    {
        printf("msgQTest thread created successfully\n");

		rc = strcpy_s( thread_name, sizeof(thread_name), "msgQTest");
        if(rc != EOK)
        {
            ERR_CHK(rc);
            return -1;
        }

        if (pthread_setname_np(mq_test_tid, thread_name) == 0)
        {
            printf("msgQTest thread name %s set successfully\n", thread_name);
        }
        else
        {
            printf("%s error occurred while setting msgQTest thread name\n", strerror(errno));
        }
    }
    else
    {
        printf("%s error occurred while creating msgQTest thread\n", strerror(errno));
        status = -1;
    }

    return status;
}


int main (int argc, char **argv)
{
    // Start up the client's server thread
    if (Client_Init() != 0)
    {
        printf("Mesh Agent Initialization failed\n");
        exit(0);
    }

    // Hang out here and wait for the threads to exit
    pthread_join(mq_server_tid, NULL);
    pthread_join(mq_test_tid, NULL);

#if defined(ENABLE_MESH_SOCKETS)
    close (mq_socket);
#else
    // Tear down the message queue
    mq_close(qd_server);
    mq_unlink(MESH_CLIENT_QUEUE_NAME);
#endif
    printf ("Client: bye\n");

    exit (0);
}

#endif
