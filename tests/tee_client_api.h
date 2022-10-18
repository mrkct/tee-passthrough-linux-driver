/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef TEE_CLIENT_API_H
#define TEE_CLIENT_API_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Defines the number of available memory references in an open session or
 * invoke command operation payload.
 */
#define TEEC_CONFIG_PAYLOAD_REF_COUNT 4

/**
 * Defines the maximum size of a single shared memory block, in bytes, of both
 * API allocated and API registered memory. There is no good value to put here
 * (limits depend on specific config used), so this define does not provide any
 * restriction in this implementation.
 */
#define TEEC_CONFIG_SHAREDMEM_MAX_SIZE ULONG_MAX

/**
 * Flag constants indicating the type of parameters encoded inside the
 * operation payload (TEEC_Operation), Type is uint32_t.
 *
 * TEEC_NONE                   The Parameter is not used
 *
 * TEEC_VALUE_INPUT            The Parameter is a TEEC_Value tagged as input.
 *
 * TEEC_VALUE_OUTPUT           The Parameter is a TEEC_Value tagged as output.
 *
 * TEEC_VALUE_INOUT            The Parameter is a TEEC_Value tagged as both as
 *                             input and output, i.e., for which both the
 *                             behaviors of TEEC_VALUE_INPUT and
 *                             TEEC_VALUE_OUTPUT apply.
 *
 * TEEC_MEMREF_TEMP_INPUT      The Parameter is a TEEC_TempMemoryReference
 *                             describing a region of memory which needs to be
 *                             temporarily registered for the duration of the
 *                             Operation and is tagged as input.
 *
 * TEEC_MEMREF_TEMP_OUTPUT     Same as TEEC_MEMREF_TEMP_INPUT, but the Memory
 *                             Reference is tagged as output. The
 *                             Implementation may update the size field to
 *                             reflect the required output size in some use
 *                             cases.
 *
 * TEEC_MEMREF_TEMP_INOUT      A Temporary Memory Reference tagged as both
 *                             input and output, i.e., for which both the
 *                             behaviors of TEEC_MEMREF_TEMP_INPUT and
 *                             TEEC_MEMREF_TEMP_OUTPUT apply.
 *
 * TEEC_MEMREF_WHOLE           The Parameter is a Registered Memory Reference
 *                             that refers to the entirety of its parent Shared
 *                             Memory block. The parameter structure is a
 *                             TEEC_MemoryReference. In this structure, the
 *                             Implementation MUST read only the parent field
 *                             and MAY update the size field when the operation
 *                             completes.
 *
 * TEEC_MEMREF_PARTIAL_INPUT   A Registered Memory Reference structure that
 *                             refers to a partial region of its parent Shared
 *                             Memory block and is tagged as input.
 *
 * TEEC_MEMREF_PARTIAL_OUTPUT  Registered Memory Reference structure that
 *                             refers to a partial region of its parent Shared
 *                             Memory block and is tagged as output.
 *
 * TEEC_MEMREF_PARTIAL_INOUT   The Registered Memory Reference structure that
 *                             refers to a partial region of its parent Shared
 *                             Memory block and is tagged as both input and
 *                             output, i.e., for which both the behaviors of
 *                             TEEC_MEMREF_PARTIAL_INPUT and
 *                             TEEC_MEMREF_PARTIAL_OUTPUT apply.
 */
#define TEEC_NONE                   0x00000000
#define TEEC_VALUE_INPUT            0x00000001
#define TEEC_VALUE_OUTPUT           0x00000002
#define TEEC_VALUE_INOUT            0x00000003
#define TEEC_MEMREF_TEMP_INPUT      0x00000005
#define TEEC_MEMREF_TEMP_OUTPUT     0x00000006
#define TEEC_MEMREF_TEMP_INOUT      0x00000007
#define TEEC_MEMREF_WHOLE           0x0000000C
#define TEEC_MEMREF_PARTIAL_INPUT   0x0000000D
#define TEEC_MEMREF_PARTIAL_OUTPUT  0x0000000E
#define TEEC_MEMREF_PARTIAL_INOUT   0x0000000F

/**
 * Flag constants indicating the data transfer direction of memory in
 * TEEC_Parameter. TEEC_MEM_INPUT signifies data transfer direction from the
 * client application to the TEE. TEEC_MEM_OUTPUT signifies data transfer
 * direction from the TEE to the client application. Type is uint32_t.
 *
 * TEEC_MEM_INPUT   The Shared Memory can carry data from the client
 *                  application to the Trusted Application.
 * TEEC_MEM_OUTPUT  The Shared Memory can carry data from the Trusted
 *                  Application to the client application.
 */
#define TEEC_MEM_INPUT   0x00000001
#define TEEC_MEM_OUTPUT  0x00000002

/**
 * Return values. Type is TEEC_Result
 *
 * TEEC_SUCCESS                 The operation was successful.
 * TEEC_ERROR_GENERIC           Non-specific cause.
 * TEEC_ERROR_ACCESS_DENIED     Access privileges are not sufficient.
 * TEEC_ERROR_CANCEL            The operation was canceled.
 * TEEC_ERROR_ACCESS_CONFLICT   Concurrent accesses caused conflict.
 * TEEC_ERROR_EXCESS_DATA       Too much data for the requested operation was
 *                              passed.
 * TEEC_ERROR_BAD_FORMAT        Input data was of invalid format.
 * TEEC_ERROR_BAD_PARAMETERS    Input parameters were invalid.
 * TEEC_ERROR_BAD_STATE         Operation is not valid in the current state.
 * TEEC_ERROR_ITEM_NOT_FOUND    The requested data item is not found.
 * TEEC_ERROR_NOT_IMPLEMENTED   The requested operation should exist but is not
 *                              yet implemented.
 * TEEC_ERROR_NOT_SUPPORTED     The requested operation is valid but is not
 *                              supported in this implementation.
 * TEEC_ERROR_NO_DATA           Expected data was missing.
 * TEEC_ERROR_OUT_OF_MEMORY     System ran out of resources.
 * TEEC_ERROR_BUSY              The system is busy working on something else.
 * TEEC_ERROR_COMMUNICATION     Communication with a remote party failed.
 * TEEC_ERROR_SECURITY          A security fault was detected.
 * TEEC_ERROR_SHORT_BUFFER      The supplied buffer is too short for the
 *                              generated output.
 * TEEC_ERROR_TARGET_DEAD       Trusted Application has panicked
 *                              during the operation.
 */

/**
 *  Standard defined error codes.
 */
#define TEEC_SUCCESS                       0x00000000
#define TEEC_ERROR_STORAGE_NOT_AVAILABLE   0xF0100003
#define TEEC_ERROR_GENERIC                 0xFFFF0000
#define TEEC_ERROR_ACCESS_DENIED           0xFFFF0001
#define TEEC_ERROR_CANCEL                  0xFFFF0002
#define TEEC_ERROR_ACCESS_CONFLICT         0xFFFF0003
#define TEEC_ERROR_EXCESS_DATA             0xFFFF0004
#define TEEC_ERROR_BAD_FORMAT              0xFFFF0005
#define TEEC_ERROR_BAD_PARAMETERS          0xFFFF0006
#define TEEC_ERROR_BAD_STATE               0xFFFF0007
#define TEEC_ERROR_ITEM_NOT_FOUND          0xFFFF0008
#define TEEC_ERROR_NOT_IMPLEMENTED         0xFFFF0009
#define TEEC_ERROR_NOT_SUPPORTED           0xFFFF000A
#define TEEC_ERROR_NO_DATA                 0xFFFF000B
#define TEEC_ERROR_OUT_OF_MEMORY           0xFFFF000C
#define TEEC_ERROR_BUSY                    0xFFFF000D
#define TEEC_ERROR_COMMUNICATION           0xFFFF000E
#define TEEC_ERROR_SECURITY                0xFFFF000F
#define TEEC_ERROR_SHORT_BUFFER            0xFFFF0010
#define TEEC_ERROR_EXTERNAL_CANCEL         0xFFFF0011
#define TEEC_ERROR_TARGET_DEAD             0xFFFF3024

/**
 * Function error origins, of type TEEC_ErrorOrigin. These indicate where in
 * the software stack a particular return value originates from.
 *
 * TEEC_ORIGIN_API          The error originated within the TEE Client API
 *                          implementation.
 * TEEC_ORIGIN_COMMS        The error originated within the underlying
 *                          communications stack linking the rich OS with
 *                          the TEE.
 * TEEC_ORIGIN_TEE          The error originated within the common TEE code.
 * TEEC_ORIGIN_TRUSTED_APP  The error originated within the Trusted Application
 *                          code.
 */
#define TEEC_ORIGIN_API          0x00000001
#define TEEC_ORIGIN_COMMS        0x00000002
#define TEEC_ORIGIN_TEE          0x00000003
#define TEEC_ORIGIN_TRUSTED_APP  0x00000004

/**
 * Session login methods, for use in TEEC_OpenSession() as parameter
 * connectionMethod. Type is uint32_t.
 *
 * TEEC_LOGIN_PUBLIC    	 No login data is provided.
 * TEEC_LOGIN_USER         	Login data about the user running the Client
 *                         	Application process is provided.
 * TEEC_LOGIN_GROUP        	Login data about the group running the Client
 *                         	Application process is provided.
 * TEEC_LOGIN_APPLICATION  	Login data about the running Client Application
 *                         	itself is provided.
 * TEEC_LOGIN_USER_APPLICATION  Login data about the user and the running
 *                          	Client Application itself is provided.
 * TEEC_LOGIN_GROUP_APPLICATION Login data about the group and the running
 *                          	Client Application itself is provided.
 */
#define TEEC_LOGIN_PUBLIC       0x00000000
#define TEEC_LOGIN_USER         0x00000001
#define TEEC_LOGIN_GROUP        0x00000002
#define TEEC_LOGIN_APPLICATION  0x00000004
#define TEEC_LOGIN_USER_APPLICATION  0x00000005
#define TEEC_LOGIN_GROUP_APPLICATION  0x00000006

/**
 * Encode the paramTypes according to the supplied types.
 *
 * @param p0 The first param type.
 * @param p1 The second param type.
 * @param p2 The third param type.
 * @param p3 The fourth param type.
 */
#define TEEC_PARAM_TYPES(p0, p1, p2, p3) \
	((p0) | ((p1) << 4) | ((p2) << 8) | ((p3) << 12))

/**
 * Get the i_th param type from the paramType.
 *
 * @param p The paramType.
 * @param i The i-th parameter to get the type for.
 */
#define TEEC_PARAM_TYPE_GET(p, i) (((p) >> (i * 4)) & 0xF)

typedef uint32_t TEEC_Result;

#ifdef __cplusplus
}
#endif

#endif
