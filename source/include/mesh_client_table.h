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

#ifndef _RDKB_MESH_CLIENT_TABLE_H_
#define _RDKB_MESH_CLIENT_TABLE_H_

#include <stdbool.h>
#include "meshsync_msgs.h"

/**************************************************************************/
/*     Mesh Client Table Fucntions                                        */
/**************************************************************************/
typedef struct _ClientTableIter ClientTableIter;

/* Fake iterator struct to make the compiler happy */
struct _ClientTableIter
{
    /* <private> */
    int       dummy1;
    void     *dummy2;
};

/**
 * @brief return the number of connected clients
 */
uint32_t Mesh_ActiveClientCount();


/**
 * @brief Initialize a client table iterator
 *
 * This function will initialize a client hash table iterator.
 * @param address of iterator to initialize
 */
void Mesh_ClientTableIterInit(ClientTableIter *iter);

/**
 * @brief Iterate to the next item in the client hash table
 *
 * This function will iterate through each element in the hash table
 * and will return it's data.
 * @param iterator for the hash
 * @param returned interface from the found node
 * @param returned mac address from the found node.
 * @param returned hostname from the found node
 * @return true if the next item was found (false at the end of the list)
 */
bool Mesh_ClientTableIterNext(ClientTableIter *iter, eMeshIfaceType *iface, char **mac, char **host);

/**
 * @brief update client hash table with a new client connect request.
 *
 * This function will either add or remove a client connection from the hash table.
 * @param interface type for the client
 * @param mac address of the client
 * @param hostname of the client
 * @param Was this a connection or disconnection?
 *
 * @return true if hash was updated
 */
bool Mesh_UpdateClientTable(eMeshIfaceType iface, char *mac, char *host, bool isConnected);

#endif /* _RDKB_MESH_CLIENT_TABLE_H_ */
