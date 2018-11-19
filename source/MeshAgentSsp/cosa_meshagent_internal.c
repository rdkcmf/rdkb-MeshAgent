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

/**************************************************************************

    module: cosa_meshagent_internal.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implements back-end apis for the COSA Data Model Library

    -------------------------------------------------------------------

    environment:

        platform independent

**************************************************************************/

#include "cosa_meshagent_internal.h"

#include "cosa_meshagent_dml.h"
#include "meshagent.h"


ANSC_HANDLE
CosaMeshAgentCreate
    (
        VOID
    )
{
	
	PCOSA_DATAMODEL_MESHAGENT       pMyObject    = (PCOSA_DATAMODEL_MESHAGENT)NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (PCOSA_DATAMODEL_MESHAGENT)AnscAllocateMemory(sizeof(COSA_DATAMODEL_MESHAGENT));

    if ( !pMyObject )
    {
    	MeshInfo("%s exit ERROR \n", __FUNCTION__);
        return  (ANSC_HANDLE)NULL;
    }

    return  (ANSC_HANDLE)pMyObject;
}


ANSC_STATUS
CosaMeshAgentInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;

    returnStatus = CosaDmlMeshAgentInit(hThisObject);
    
    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {

	MeshInfo("%s Exit ERROR \n", __FUNCTION__);
        return  returnStatus;
    }
    
    return returnStatus;
}


ANSC_STATUS
CosaMeshAgentRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PCOSA_DATAMODEL_MESHAGENT            pMyObject    = (PCOSA_DATAMODEL_MESHAGENT)hThisObject;

    /* Remove self */
    AnscFreeMemory((ANSC_HANDLE)pMyObject);
    MeshInfo("%s EXIT \n", __FUNCTION__);

	return returnStatus;
}

