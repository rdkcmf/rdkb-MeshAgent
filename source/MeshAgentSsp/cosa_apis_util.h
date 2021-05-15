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

/*
 * cosa_apis_util.h
 *
 *  Created on: Mar 14, 2017
 */

#ifndef MESHAGENT_SOURCE_MESHAGENT_MESHUTILS_H_
#define MESHAGENT_SOURCE_MESHAGENT_MESHUTILS_H_
#include <stdbool.h>

typedef enum {
    MESH_STOP = 0,
    MESH_START,
    MESH_RESTART
} eMeshSysCtlState;

int Mesh_SyseventGetInt(const char *name);
int Mesh_SyseventSetInt(const char *name, int int_value);
int Mesh_SyseventGetStr(const char *name, unsigned char *out_value, int outbufsz);
int Mesh_SyseventSetStr(const char *name, unsigned char *value, int bufsz, bool toArm);
int Mesh_SysCfgGetInt(const char *name);
int Mesh_SysCfgSetInt(const char *name, int int_value);
int Mesh_SysCfgGetStr(const char *name, unsigned char *out_value, int outbufsz);
int Mesh_SysCfgSetStr(const char *name, unsigned char *str_value, bool toArm);

int svcagt_get_service_state (const char *svc_name);
int svcagt_set_service_state (const char *svc_name, eMeshSysCtlState state);

#endif /* MESHAGENT_SOURCE_MESHAGENT_MESHUTILS_H_ */
