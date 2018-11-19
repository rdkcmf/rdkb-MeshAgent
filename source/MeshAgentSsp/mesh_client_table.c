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

#ifndef _RDKB_MESH_CLIENT_TABLE_C_
#define _RDKB_MESH_CLIENT_TABLE_C_

#include <stdlib.h>
#include <string.h>
#include "mesh_client_table.h"
#include "meshagent.h"

/*
 * @file mesh_client_table.c
 * @brief Mesh Agent Client Table
 *
 * If we get into trouble here with concurency, we'll have to lock down pool access
 */

/**************************************************************************/
/*      LOCAL VARIABLES:                                                  */
/**************************************************************************/
// Maximum number of connected clients that we are going to support in the pool
#define MAX_CONNECTED_CLIENTS 100

// Maximum number of hash buckets - should be a prime number
#define MAX_NUMBER_HASH_BUCKETS 19

const int INVALID_ITERATOR_POS = -1;

static uint32_t sHashItemCount = 0;

// This is the connected client data
typedef struct _ClientItem {
    eMeshIfaceType  iface;                   // Interface
    char            mac [MAX_MAC_ADDR_LEN];  // MAC address
    char            host[MAX_HOSTNAME_LEN];  // Hostname
} ClientItem;

// These are the hash items
typedef struct _HashItem {
    bool             inUse;                  // true when in use/false if available
    ClientItem       client;                 // Connected client data
    struct _HashItem *next;                   // Pointer to the next item in the bucket list
} HashItem;

// These are the hash table entries
typedef struct _HashTableEntry {
    int             count; // keep track of how many entries we have per bucket
    HashItem       *head;  // hash entry list for this bucket
} HashTableEntry;

// Real Client table iterator
typedef struct _RealClientTableIter
{
    int position;
    HashItem *lastItem;
} RealClientTableIter;


// Fixed pool of hash items to select from
HashItem hashItemPool[MAX_CONNECTED_CLIENTS] = {0};

// Hash Table
HashTableEntry hashTable[MAX_NUMBER_HASH_BUCKETS] = {0};


/**************************************************************************/
/*      Function Prototypes:                                                  */
/**************************************************************************/
HashItem *HashAlloc();
bool HashFree(HashItem *item);
bool HashAdd(eMeshIfaceType iface, char *mac, char *host);
bool HashDelete(eMeshIfaceType iface, char *mac);
HashItem *HashFind(eMeshIfaceType iface, char *mac);
unsigned int HashMe(eMeshIfaceType iface, char *mac);
void DumpHashStats();
void DumpClientTable();

/**
 * @brief Unique hash function based on mac address and connection interface
 *
 * For our 1st pass at this, we are going to add up the mac bytes and then divide
 * by the number of buckets.
 */
unsigned int HashMe(eMeshIfaceType iface, char *mac)
{
    unsigned int hashIdx = 0;
    const char s[2] = ":";
    char hashStr[MAX_MAC_ADDR_LEN] = {0};
    char *token;

    // Copy over the string so we don't mess it up.
    strncpy(hashStr, mac, sizeof(hashStr)-1);

    /* get the first token */
    token = strtok(hashStr, s);

    /* walk through other tokens */
    while( token != NULL )
    {
       hashIdx += (int)strtol(token, NULL, 16);
       token = strtok(NULL, s);
    }

    return (hashIdx%MAX_NUMBER_HASH_BUCKETS);
}

/**
 * @brief Free Hash entry
 *
 */
bool HashFree(HashItem *item)
{
    if (item) {
        memset(item, 0, sizeof(HashItem)); // clear out the item
    }

    return true;
}

/**
 * @brief allocate entry
 */
HashItem *HashAlloc()
{
    int i=0;
    HashItem *item = NULL;
    // find an unused entry in the hash pool
    for (i=0;i < MAX_CONNECTED_CLIENTS;i++)
    {
        if (!hashItemPool[i].inUse) {
            hashItemPool[i].inUse = true; // mark item as in use
            item = &hashItemPool[i];
            break;
        }
    }
    return item;
}

/**
 * @brief find an entry in the hash table
 */
HashItem *HashFind(eMeshIfaceType iface, char *mac)
{
    int index = HashMe(iface, mac);
    HashItem *item = hashTable[index].head;

    while (item != NULL) {
        if (item->client.iface == iface && strcmp(item->client.mac, mac) == 0) {
            // Found the item!
            break;
        }
        item = item->next;
    }
    return item;
}

/**
 * @ brief add entry to client hash table
 */
bool HashAdd(eMeshIfaceType iface, char *mac, char *host)
{
    bool success = false;

    // add client connection if it isn't already there
    if (HashFind(iface, mac) == NULL) {
        // item doesn't exist, add it!
        HashItem *newItem = HashAlloc();
        if (newItem) {
            int idx = HashMe(iface, mac);
            // Copy data into the has entry
            newItem->client.iface = iface;
            if (mac != NULL) {
                strncpy(newItem->client.mac, mac, sizeof(newItem->client.mac)-1);
            }
            if (host != NULL) {
                strncpy(newItem->client.host, host, sizeof(newItem->client.host)-1);
            }
            // Now find our place in the hash bucket
            HashItem *pItem = hashTable[idx].head;
            if (pItem == NULL) {
                // This is the 1st item in the hash
                hashTable[idx].head = newItem;
            } else {
                // wander out to the end of the bucket.
                while (pItem->next != NULL) {
                    pItem = pItem->next;
                }
                pItem->next = newItem;
            }
            hashTable[idx].count++;
            sHashItemCount++;
            success = true;
            // MeshInfo("%s added to bucket %d as the %d item\n", mac, idx, hashTable[idx].count);
        } else {
            MeshError("ERROR! Out of memory in the connected client Pool!\n");
        }
    } else {
        MeshWarning("%s Already exists in the hash, not added\n", mac);
    }

    return success;
}

/**
 * @brief remove entry from client table
 */
bool HashDelete(eMeshIfaceType iface, char *mac)
{
    bool success = false;

    if (HashFind(iface, mac) != NULL) {
        // lookup entry in hash buckets
        // remove item
        int idx = HashMe(iface, mac);

        HashItem *nextItem = hashTable[idx].head;
        HashItem *prevItem = nextItem;

        while (nextItem->client.iface != iface && strcmp(nextItem->client.mac, mac) != 0) {
            prevItem = nextItem;
            nextItem = nextItem->next;
        }

        if (nextItem == hashTable[idx].head) {
            // found our entry at the front of the hash bucket
            hashTable[idx].head = nextItem->next;
            HashFree(nextItem);
        } else {
            // we found our item in the nextItem, jump over it in prevItem
            prevItem->next = nextItem->next;
            HashFree(nextItem);
        }
        success = true;
        sHashItemCount--;
        hashTable[idx].count--;
        // MeshInfo("%s removed from bucket %d as the %d item\n", mac, idx, hashTable[idx].count);
    } else {
        MeshWarning("%s Does not exist in the hash, not deleted\n", mac);
    }

    return success;
}

/**
 * @brief return the number of connected clients
 */
uint32_t Mesh_ActiveClientCount()
{
    return sHashItemCount;
}

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
bool Mesh_UpdateClientTable(eMeshIfaceType iface, char *mac, char *host, bool isConnected)
{
    bool success = false;

    if (mac && mac[0] != '\0') {
        if (isConnected) {
            // add client if not in table
            success = HashAdd(iface, mac, host);
        } else {
            // remove client if in the table
            success = HashDelete(iface, mac);
        }

        // DumpHashStats();
    } else {
        MeshError("Error adding client to connected table - bad mac\n");
    }


    return success;
}

/**
 * @brief Dump out hash stats
 */
void DumpHashStats() {
    int i = 0;
    int conTotal = 0;

    // Print out number of connections in each bucket
    for (i=0; i<MAX_NUMBER_HASH_BUCKETS;i++) {
        MeshInfo("Connection count for bucket %d is %d\n", i, hashTable[i].count);
        conTotal += hashTable[i].count;
    }

    // Print out total number of connections
    if (conTotal == sHashItemCount) {
        MeshInfo("Total number of connections = %d\n", conTotal);
    } else {
        MeshError("Connection count mismatch! Bucket count %d != Total Connections %d\n", conTotal, sHashItemCount);
    }
}

void DumpClientTable() {
    int idx = 0;
    MeshInfo("DumpClientTable \n");

    // Print out number of connections in each bucket
    for (idx=0; idx<MAX_NUMBER_HASH_BUCKETS;idx++) {
        HashItem *item = hashTable[idx].head;
        if (hashTable[idx].count) {
            MeshInfo("Bucket %d count %d\n", idx, hashTable[idx].count);
            while(item != NULL) {
                MeshInfo("mac %s iface %d\n", item->client.mac, (int) item->client.iface);
                item = item->next;
            }
        }
    }
}

/**
 * @brief Initialize a client table iterator
 *
 * This function will initialize a client hash table iterator.
 * @param address of iterator to initialize
 */
void Mesh_ClientTableIterInit(ClientTableIter *cIter)
{
    RealClientTableIter *iter = (RealClientTableIter *) cIter;
    if (iter) {
        iter->position = INVALID_ITERATOR_POS;
        iter->lastItem = NULL;
    }
}

/**
 * @brief Iterate to the next item in the client hash table
 *
 * This function will iterate through each element in the hash table
 * and will return it's data.
 * @param iterator for the hash
 * @param returned interface from the found node
 * @param returned mac address from the found node.
 * @return true if the next item was found (false at the end of the list)
 */
bool Mesh_ClientTableIterNext(ClientTableIter *cIter, eMeshIfaceType *iface, char **mac, char **host)
{
    bool found = false;
    RealClientTableIter *iter = (RealClientTableIter *) cIter;

    if (iter) {
        int pos = iter->position;

        if (pos == INVALID_ITERATOR_POS) {
            // This is the 1st time into the hash for this iterator.
            // we're going to have to find the 1st filled bucket.
            int i;
            for (i=0;i<MAX_NUMBER_HASH_BUCKETS;i++) {
                if (hashTable[i].head != NULL) {
                    iter->position = i;
                    iter->lastItem = hashTable[i].head;
                    found = true;
                    break;
                }
            }
        } else if (pos < MAX_NUMBER_HASH_BUCKETS) {
            HashItem *node = hashTable[iter->position].head;
            while(node && node != iter->lastItem)
            {
                node = node->next;
            }

            if (node == NULL) {
                // Something bad happened because we couldn't find the last Item we searched for
                // we'll just let it dump out
            } else if (node->next != NULL) {
                // we found the next item in the bucket
                iter->lastItem = node->next;
                found = true;
            } else {
                // so our next node in the bucket is null, we have to move to the next bucket
                pos++;
                while (!found && pos<MAX_NUMBER_HASH_BUCKETS)
                {
                    if (hashTable[pos].head) {
                        found = true;
                        iter->lastItem = hashTable[pos].head;
                        iter->position = pos;
                    }
                    pos++;
                }
            }
        }

        if (found) {
            *iface = iter->lastItem->client.iface;
            *mac = iter->lastItem->client.mac;
            *host = iter->lastItem->client.host;
        } else {
            iter->position = INVALID_ITERATOR_POS;
            iter->lastItem = NULL;
        }
    }

    return found;
}

#endif /* _RDKB_MESH_CLIENT_TABLE_C_ */
