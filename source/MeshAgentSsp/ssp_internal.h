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

/**
* @file ssp_internal.h
 *
 * @description This is the template file of ssp_internal.h for ccsp component.
 */

#ifndef  _SSP_INTERNAL_H_
#define  _SSP_INTERNAL_H_

#include "ccsp_component_helper.h"
/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/

#define  CCSP_COMMON_COMPONENT_HEALTH_Red                   1
#define  CCSP_COMMON_COMPONENT_HEALTH_Yellow                2
#define  CCSP_COMMON_COMPONENT_HEALTH_Green                 3

#define  CCSP_COMMON_COMPONENT_STATE_Initializing           1
#define  CCSP_COMMON_COMPONENT_STATE_Running                2
#define  CCSP_COMMON_COMPONENT_STATE_Blocked                3
#define  CCSP_COMMON_COMPONENT_STATE_Paused                 3

#define  CCSP_COMMON_COMPONENT_FREERESOURCES_PRIORITY_High  1
#define  CCSP_COMMON_COMPONENT_FREERESOURCES_PRIORITY_Low   2

#define  CCSP_COMPONENT_ID                             		"com.cisco.spvtg.ccsp.meshagent"
#define  CCSP_COMPONENT_NAME                           		"com.cisco.spvtg.ccsp.meshagent"
#define  CCSP_COMPONENT_VERSION                       		1
#define  CCSP_COMPONENT_PATH                           		"/com/cisco/spvtg/ccsp/meshagent"

#define  MESSAGE_BUS_CONFIG_FILE                            "msg_daemon.cfg"
#define  CCSP_MESHAGENT_START_CFG_FILE						"MeshAgent.cfg"

/**
 * @brief Defines component Structure
 */
typedef  struct
_COMPONENT_COMMON
{
    char*                           Name;
    ULONG                           Version;
    char*                           Author;
    ULONG                           Health;
    ULONG                           State;

    BOOL                            LogEnable;
    ULONG                           LogLevel;

    ULONG                           MemMaxUsage;
    ULONG                           MemMinUsage;
    ULONG                           MemConsumed;
}
COMPONENT_COMMON,  *PCOMPONENT_COMMON ;

/**
 * @brief Initializes component
 * param[in] component_com object
 */
#define ComponentCommonDmInit(component_com)                                          \
        {                                                                                  \
            AnscZeroMemory(component_com, sizeof(COMPONENT_COMMON));             \
            component_com->Name        = NULL;                                        \
            component_com->Version     = 1;                                           \
            component_com->Author      = NULL;                                        \
            component_com->Health      = CCSP_COMMON_COMPONENT_HEALTH_Red;            \
            component_com->State       = CCSP_COMMON_COMPONENT_STATE_Running;         \
            if(g_iTraceLevel >= CCSP_TRACE_LEVEL_EMERGENCY)                                \
                component_com->LogLevel = (ULONG) g_iTraceLevel;                      \
            component_com->LogEnable   = TRUE;                                        \
            component_com->MemMaxUsage = 0;                                           \
            component_com->MemMinUsage = 0;                                           \
            component_com->MemConsumed = 0;                                           \
        }

/**
 * @brief clears component
 * param[in] component_com object
 */
#define  ComponentCommonDmClean(component_com)                                        \
         {                                                                                  \
            if ( component_com->Name )                                                \
            {                                                                               \
                AnscFreeMemory(component_com->Name);                                  \
            }                                                                               \
                                                                                            \
            if ( component_com->Author )                                              \
            {                                                                               \
                AnscFreeMemory(component_com->Author);                                \
            }                                                                               \
         }

/**
 * @brief free agent component
 * param[in] component_com object
 */
#define  ComponentCommonDmFree(component_com)                                         \
         {                                                                                  \
            ComponentCommonDmClean(component_com);                                    \
            AnscFreeMemory(component_com);                                            \
         }

int  cmd_dispatch(int  command);

/**
 * @brief ssp_create function definition to create component
 */
ANSC_STATUS
ssp_create
(   
	PCCSP_COMPONENT_CFG	pMeshCfg
);

/**
 * @brief ssp_engage function definition to engage component
 */
ANSC_STATUS
ssp_engage
(   
    PCCSP_COMPONENT_CFG pMeshCfg
);

/**
 * @brief ssp_cancel function definition to cancel component
 */
ANSC_STATUS
ssp_cancel
(   
    PCCSP_COMPONENT_CFG pMeshCfg
);


char*
ssp_CcdIfGetComponentName
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetComponentVersion
    (
        ANSC_HANDLE                     hThisObject
    );

char*
ssp_CcdIfGetComponentAuthor
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetComponentHealth
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetComponentState
    (
        ANSC_HANDLE                     hThisObject
    );

BOOL
ssp_CcdIfGetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_CcdIfSetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject,
        BOOL                            bEnabled
    );

ULONG
ssp_CcdIfGetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_CcdIfSetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject,
        ULONG                           LogLevel
    );

ULONG
ssp_CcdIfGetMemMaxUsage
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetMemMinUsage
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetMemConsumed
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_CcdIfApplyChanges
    (
        ANSC_HANDLE                     hThisObject
    );


#endif
