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

#ifndef  _COSA_MESHAGENT_DML_H
#define  _COSA_MESHAGENT_DML_H


#include "slap_definitions.h"
#include "meshsync_msgs.h"

ANSC_STATUS
CosaDmlServiceManagerInit
    (
        ANSC_HANDLE                 hThisObject
    );


/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_Mesh.

    *  MeshAgent_GetParamBoolValue
    *  OVS_GetParamBoolValue
    *  MeshAgent_GetParamStringValue
    *  MeshAgent_SetParamBoolValue
    *  OVS_SetParamBoolValue
    *  MeshAgent_SetParamStringValue
    *  MeshAgent_Validate
    *  MeshAgent_Commit
    *  MeshAgent_Rollback

***********************************************************************/
BOOL
MeshAgent_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
OVS_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

ULONG
MeshAgent_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );
    
BOOL
MeshAgent_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    );

BOOL
MeshAgent_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                        puLong
    );

BOOL
MeshAgent_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
OVS_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
MeshAgent_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );
    

BOOL
MeshAgent_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
MeshAgent_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
MeshAgent_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

extern MeshSync_MsgItem meshSyncMsgArr[];
#endif //_COSA_MESHAGENT_DML_H

