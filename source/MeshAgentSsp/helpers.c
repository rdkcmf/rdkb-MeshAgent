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

#include <errno.h>
#include <string.h>
#include <msgpack.h>
#include "ccsp_trace.h"
#include "helpers.h"
#include "cosa_webconfig_api.h"
/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
#define MB_ERROR                   -1 

/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/
/* none */

/*----------------------------------------------------------------------------*/
/*                            File Scoped Variables                           */
/*----------------------------------------------------------------------------*/
//static const uint8_t cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
msgpack_object* __finder( const char *name, 
                          msgpack_object_type expect_type,
                          msgpack_object_map *map );
int process_meshdocparams( meshbackhauldoc_t *e, msgpack_object_map *map );
int process_meshbackhauldoc( meshbackhauldoc_t *pm, int num, ...);
/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
void* helper_convert( const void *buf, size_t len,
                      size_t struct_size, const char *wrapper,
                      msgpack_object_type expect_type, bool optional,
                      process_fn_t process,
                      destroy_fn_t destroy )
{
    void *p = malloc( struct_size );

    if( NULL == p )
    {
        errno = HELPERS_OUT_OF_MEMORY;
    }
    else
    {
        memset( p, 0, struct_size );

        if( NULL != buf && 0 < len )
        {
            size_t offset = 0;
            msgpack_unpacked msg;
            msgpack_unpack_return mp_rv;

            msgpack_unpacked_init( &msg );

            /* The outermost wrapper MUST be a map. */
            mp_rv = msgpack_unpack_next( &msg, (const char*) buf, len, &offset );

            if( (MSGPACK_UNPACK_SUCCESS == mp_rv) && (0 != offset) &&
                (MSGPACK_OBJECT_MAP == msg.data.type) )
            {
                msgpack_object *inner;
                msgpack_object *subdoc_name;
                msgpack_object *version;
                msgpack_object *transaction_id;

                if( NULL != wrapper && 0 == strncmp(wrapper,"parameters",strlen("parameters")))
                {
                    inner = __finder( wrapper, expect_type, &msg.data.via.map );

                    if( ((NULL != inner) && (0 == (process)(p, 1, inner))) ||
                              ((true == optional) && (NULL == inner)) )
                    {
                         msgpack_unpacked_destroy( &msg );
                         errno = HELPERS_OK;
                         return p;
                    }
                    else
                    {
                         errno = HELPERS_INVALID_FIRST_ELEMENT;
                    }
                }
                else if( NULL != wrapper && 0 != strcmp(wrapper,"parameters"))
                {
                    inner = __finder( wrapper, expect_type, &msg.data.via.map );
                    subdoc_name =  __finder( "subdoc_name", expect_type, &msg.data.via.map );
                    version =  __finder( "version", expect_type, &msg.data.via.map );
                    transaction_id =  __finder( "transaction_id", expect_type, &msg.data.via.map );

                    if( ((NULL != inner) && (0 == (process)(p,4, inner, subdoc_name, version, transaction_id))) ||
                              ((true == optional) && (NULL == inner)) )
                    {
                         msgpack_unpacked_destroy( &msg );
                         errno = HELPERS_OK;
                         return p;
                    }
                    else
                    {
                         errno = HELPERS_INVALID_FIRST_ELEMENT;
                    }
                }

              }
            msgpack_unpacked_destroy( &msg );
            if(NULL!=p)
            {
               (destroy)( p );
                p = NULL;
            }

        }
    }
    return p;
}
/* See helper.h for details. */
meshbackhauldoc_t* meshbackhauldoc_convert( const void *buf, size_t len )
{
        return helper_convert( buf, len, sizeof(meshbackhauldoc_t), "mesh",
                            MSGPACK_OBJECT_ARRAY, true,
                           (process_fn_t) process_meshbackhauldoc,
                           (destroy_fn_t) meshbackhauldoc_destroy );
}

/* See helper.h for details. */
void meshbackhauldoc_destroy( meshbackhauldoc_t *mb )
{
    if( NULL != mb )
    {
        if( NULL != mb->subdoc_name )
        {
            free( mb->subdoc_name );
        }
        free( mb );
    }
}

/* See webcfgdoc.h for details. */
const char* meshbackhauldoc_strerror( int errnum )
{
    struct error_map {
        int v;
        const char *txt;
    } map[] = {
        { .v = MB_OK,                               .txt = "No errors." },
        { .v = MB_OUT_OF_MEMORY,                    .txt = "Out of memory." },
        { .v = MB_INVALID_FIRST_ELEMENT,            .txt = "Invalid first element." },
        { .v = MB_INVALID_VERSION,                  .txt = "Invalid 'version' value." },
        { .v = MB_INVALID_OBJECT,                .txt = "Invalid 'value' array." },
        { .v = 0, .txt = NULL }
    };
    int i = 0;

    while( (map[i].v != errnum) && (NULL != map[i].txt) ) { i++; }

    if( NULL == map[i].txt )
    {
        //CcspTraceWarning(("----meshbackhauldoc_strerror----\n"));
        return "Unknown error.";
    }

    return map[i].txt;
}

/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/

msgpack_object* __finder( const char *name,
                          msgpack_object_type expect_type,
                          msgpack_object_map *map )
{
    uint32_t i;

    for( i = 0; i < map->size; i++ )
    {
        if( MSGPACK_OBJECT_STR == map->ptr[i].key.type )
        {
            if( expect_type == map->ptr[i].val.type )
            {
                if( 0 == match(&(map->ptr[i]), name) )
                {
                    return &map->ptr[i].val;
                }
            }
            else if(MSGPACK_OBJECT_STR == map->ptr[i].val.type)
            {
                if(0 == strncmp(map->ptr[i].key.via.str.ptr, name, strlen(name)))
                {
                    return &map->ptr[i].val;
                }

             }
             else
            {
                if(0 == strncmp(map->ptr[i].key.via.str.ptr, name, strlen(name)))
                {
                    return &map->ptr[i].val;
                }

             }
            }
        }
     errno = HELPERS_MISSING_WRAPPER;
    return NULL;
}

/**
 *  Convert the msgpack map into the doc_t structure.
 *
 *  @param e    the entry pointer
 *  @param map  the msgpack map pointer
 *
 *  @return 0 on success, error otherwise
 */
int process_meshdocparams ( meshbackhauldoc_t *mb, msgpack_object_map *mapobj )
{
    int left = mapobj->size;
    uint8_t objects_left = 0x02;
    msgpack_object_kv *p;
    p = mapobj->ptr;
    while( (0 < objects_left) && (0 < left--) )
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
              if( MSGPACK_OBJECT_BOOLEAN == p->val.type )
              {
                  if( 0 == match(p, "Enable") )
                  {
                      mb->mesh_enable = p->val.via.boolean;
                      objects_left &= ~(1 << 0);
                  }
                  if( 0 == match(p, "Ethbhaul") )
                  {
                      mb->ethernetbackhaul_enable = p->val.via.boolean;
                      objects_left &= ~(1 << 1);
                  }
              }
        }
        p++;
    }

    if( 1 & objects_left ) {
    } else {
        errno = MB_OK;
    }

    return (0 == objects_left) ? 0 : -1;
}

int process_meshbackhauldoc( meshbackhauldoc_t *mb,int num, ... )
{
    va_list valist;
    va_start(valist, num);


    msgpack_object *obj = va_arg(valist, msgpack_object *);
    msgpack_object_map *mapobj = &obj->via.map;

    msgpack_object *obj1 = va_arg(valist, msgpack_object *);
    mb->subdoc_name = strndup( obj1->via.str.ptr, obj1->via.str.size );

    msgpack_object *obj2 = va_arg(valist, msgpack_object *);
    mb->version = (uint32_t) obj2->via.u64;

    msgpack_object *obj3 = va_arg(valist, msgpack_object *);
    mb->transaction_id = (uint16_t) obj3->via.u64;

    va_end(valist);
    if (0 != process_meshdocparams( mb,mapobj ))
    {
        return -1;
    }

    return 0;
}
