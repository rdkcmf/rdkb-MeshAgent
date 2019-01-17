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

#ifndef _MESHAGENT_H_
#define _MESHAGENT_H_
#include <stdbool.h>
#include "meshsync_msgs.h"

#define MESHAGENT_COMPONENT_NAME		"MeshAgent"

/**
 * @brief Enables or disables debug logs.
 */
#define MESHAGENT_LOG_ERROR                 0
#define MESHAGENT_LOG_INFO                  1
#define MESHAGENT_LOG_WARNING               2
#define MESHAGENT_LOG_DEBUG                 3
#define MeshError(...)                   _MESHAGENT_LOG(MESHAGENT_LOG_ERROR, __VA_ARGS__)
#define MeshInfo(...)                    _MESHAGENT_LOG(MESHAGENT_LOG_INFO, __VA_ARGS__)
#define MeshWarning(...)                 _MESHAGENT_LOG(MESHAGENT_LOG_WARNING, __VA_ARGS__)
#define MeshDebug(...)                   _MESHAGENT_LOG(MESHAGENT_LOG_DEBUG, __VA_ARGS__)


typedef enum {
  POD_XHS_PORT=0,
  POD_ETH_PORT
} detectionMsg;

/**
 * @brief Initializes the Message Bus and registers component with the stack.
 *
 * @param[in] name Component Name.
 * @return status 0 for success and 1 for failure
 */
int msgBusInit(const char *name);

/**
 * @brief LOGInit Initialize RDK Logger
 */
void LOGInit();

/**
 * @brief _MESHAGENT_LOG MESHAGENT RDK logger API
 */

void _MESHAGENT_LOG(unsigned int level, const char *msg, ...)
    __attribute__((format (printf, 2, 3)));

/**
 * @brief Mesh Agent Get Url
 *
 * This function will set the url and notify the Mesh vendor of the change
 */
int Mesh_GetUrl(char *retBuf, int bufSz);

/**
 * @brief Mesh Agent Set Url
 *
 * This function will set the url and notify the Mesh vendor of the change
 */
bool Mesh_SetUrl(char *url, bool init);

/**
 * @brief Mesh Agent Enable/Disable
 *
 * This function will enable/disable the Mesh service
 */
bool Mesh_SetEnabled(bool enable, bool init);

/**
 * @brief Mesh Agent Set Mesh State
 *
 * This function will set the state of the Mesh Service.
 * Full, Monitor, etc.
 */
bool Mesh_SetMeshState(eMeshStateType state, bool init, bool commit);

/**
 * @brief Mesh Agent Ge tEnable/Disable
 *
 * This function will enable/disable the Mesh service
 */
bool Mesh_GetEnabled(const char *name);

/**
 * @brief Mesh Agent Update Connected Device
 *
 * This function will update the connected device table and notify
 * Mesh of changes
 */
bool Mesh_UpdateConnectedDevice(char *mac, char *iface, char *host, char *status);

#endif /* _MESHAGENT_H_ */
