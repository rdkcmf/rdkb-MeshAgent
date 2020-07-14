/*
 * Copyright 2019 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef  _COSA_WEBCONFIG_API_H
#define  _COSA_WEBCONFIG_API_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <webconfig_framework.h>
#include "helpers.h"

#define SUBDOC_COUNT 1

#define MESH_CACHE_SIZE 4
#define BLOCK_SIZE 32
#define VAL_BLOCK_SIZE 129 // for ipv6 address 128 + 1 size is needed

#define MESH_ENABLE                  "mesh_enable"
#define ETHERNET_BACKHAUL_ENABLE     "ethbhaul_enable"

#ifdef WEBCFG_TEST_SIM

#define NACK_SIMULATE_FILE "/tmp/sim_nack"
#define TIMEOUT_SIMULATE_FILE "/tmp/sim_timeout"

#endif

enum {
    MB_OK                       = HELPERS_OK,
    MB_OUT_OF_MEMORY            = HELPERS_OUT_OF_MEMORY,
    MB_INVALID_FIRST_ELEMENT    = HELPERS_INVALID_FIRST_ELEMENT,
    MB_MISSING_PM_ENTRY         = HELPERS_MISSING_WRAPPER,
    MB_INVALID_OBJECT,
    MB_INVALID_VERSION,
};              

typedef struct {
    bool mesh_enable;      
    bool ethernetbackhaul_enable;
} t_cache;

t_cache mb_cache; 
t_cache mb_cache_bkup; 

uint32_t getBlobVersion(char* subdoc);
int setBlobVersion(char* subdoc,uint32_t version);
void webConfigFrameworkInit() ;

void clear_mb_cache(t_cache *tmp_mb_cache);
void print_mb_cache(t_cache *tmp_mb_cache);
int clear_mb_cache_DB(t_cache *tmp_mb_cache);
int apply_mb_cache_ToDB(t_cache *tmp_mb_cache);
int set_meshbackhaul_conf(meshbackhauldoc_t *mb,t_cache *cache);
void backup_mb_cache(t_cache *tmp_mb_cache,t_cache *tmp_mb_cache_bkup);

void init_mb_cache(t_cache *tmp_mb_cache);

pErr Process_MB_WebConfigRequest(void *Data);
int rollback_MeshBackhaul() ;
void freeResources_MeshBackhaul(void *arg);
#endif
