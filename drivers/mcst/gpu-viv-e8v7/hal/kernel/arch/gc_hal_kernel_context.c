/****************************************************************************
*
*    The MIT License (MIT)
*
*    Copyright (c) 2014 - 2024 Vivante Corporation
*
*    Permission is hereby granted, free of charge, to any person obtaining a
*    copy of this software and associated documentation files (the "Software"),
*    to deal in the Software without restriction, including without limitation
*    the rights to use, copy, modify, merge, publish, distribute, sublicense,
*    and/or sell copies of the Software, and to permit persons to whom the
*    Software is furnished to do so, subject to the following conditions:
*
*    The above copyright notice and this permission notice shall be included in
*    all copies or substantial portions of the Software.
*
*    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
*    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
*    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
*    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
*    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
*    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
*    DEALINGS IN THE SOFTWARE.
*
*****************************************************************************
*
*    The GPL License (GPL)
*
*    Copyright (C) 2014 - 2024 Vivante Corporation
*
*    This program is free software; you can redistribute it and/or
*    modify it under the terms of the GNU General Public License
*    as published by the Free Software Foundation; either version 2
*    of the License, or (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program; if not, write to the Free Software Foundation,
*    Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
*
*****************************************************************************
*
*    Note: This software is released under dual MIT and GPL licenses. A
*    recipient may use this file under the terms of either the MIT license or
*    GPL License. If you wish to use only one license not the other, you can
*    indicate your decision by deleting one of the above license notices in your
*    version of this file.
*
*****************************************************************************/

/*
 *
 * gckCONTEXT object initialization for architecture dependent user HAL layers.
 *
 *
 *                  ---------------------------------------
 *                  CONTEXT BUFFER MANAGEMENT FLOW OVERVIEW
 *                  ---------------------------------------
 *            |
 * ===========|=============================================== COMMIT 1 ========
 *            |
 *            |   First COMMIT call; this is a new context for the kernel,
 *            |   therefore context buffer is invoked. At this point there
 *            |   are no deltas associated with it. After the context is
 *            |   scheduled, the current context buffer advances to the
 *            |   next one ("Context Buffer 2" in this case).
 *            |
 *            |   "State Delta 1" is passed from the user together with the
 *            |   "Command Buffer 1". This state delta represents state
 *            |   changes that happen in "Command Buffer 1". It gets asso-
 *            |   ciated with all context buffers. The association happens
 *            |   only during the context switch.
 *            |
 *  +-------------------+
 *  | Context Buffer 1  |
 *  +---------+---------+
 *            |
 *  +---------+---------+        +---------------+
 *  | Command Buffer 1  |  ....  | State Delta 1 |
 *  +---------+---------+        +---------------+
 *            |                    associations made:
 *            |                  +-------------------+        +---------------+
 *            |                  | Context Buffer 1  | -----> | State Delta 1 |
 *            |                  +-------------------+        +---------------+
 *            |                  +-------------------+        +---------------+
 *            |                  | Context Buffer 2  | -----> | State Delta 1 |
 *            |                  +-------------------+        +---------------+
 *            |
 * ===========|=============================================== COMMIT 2 ========
 *            |
 *            |   Since the user cannot know whether the context switch will
 *            |   happen during the next commit, after COMMIT 1 is finished,
 *            |   the user automatically moves to using "State Delta 2". This
 *            |   is because "State Delta 1" is already associated with both
 *            |   context buffers and becomes read-only after that.
 *            |
 *            |   No context switch this time, "State Delta 2" is not being
 *            |   associated with any of the context buffers and comes back
 *            |   to the user as unreferenced. This is the signal to the user
 *            |   that instead of moving on to the next state delta, it should
 *            |   merge this delta with the previous one and then stay at the
 *            |   same state delta ("State Delta 2" in this case).
 *            |
 *  +---------+---------+        +---------------+
 *  | Command Buffer 2  |  ....  | State Delta 2 |
 *  +---------+---------+        +---------------+
 *            |
 * ===========|=============================================== COMMIT 3 ========
 *            |
 *            |   A COMMIT from another thread occurred after COMMIT 2 and
 *            |   before COMMIT 3, forcing a context switch in this thread.
 *            |   All associated state deltas are applied to the current
 *            |   context buffer to update its state values. In this case we
 *            |   update "Context Buffer 2" with "State Delta 1".
 *            |
 *            |   "State Delta 2" is passed from the user together with the
 *            |   "Command Buffer 3", which is then associated with all
 *            |   context buffers.
 *            |
 *            |   The user seeing that the delta became associated, moves
 *            |   to the next state delta - "State Delta 3".
 *            |
 *  +---------+---------+        +---------------+
 *  | Context Buffer 2  | <----- | State Delta 1 |
 *  +---------+---------+        +---------------+
 *            |
 *  +---------+---------+        +---------------+
 *  | Command Buffer 3  |  ....  | State Delta 2 |
 *  +---------+---------+        +---------------+            +---------------+
 *            |                    associated:           +--> | State Delta 1 |
 *            |                  +-------------------+   |    +---------------+
 *            |                  | Context Buffer 1  | --+    +---------------+
 *            |                  +-------------------+   +--> | State Delta 2 |
 *            |                                               +---------------+
 *            |                  +-------------------+        +---------------+
 *            |                  | Context Buffer 2  | -----> | State Delta 2 |
 *            |                  +-------------------+        +---------------+
 *            |
 * ===========|=============================================== COMMIT 4 ========
 *            |
 *            |   A COMMIT from another thread occurred after COMMIT 3 and
 *            |   before COMMIT 4, forcing a context switch in this thread.
 *            |   All associated state deltas are applied to the current
 *            |   context buffer to update its state values. In this case we
 *            |   update "Context Buffer 1" with "State Delta 1" and
 *            |   "State Delta 2".
 *            |
 *  +---------+---------+        +---------------+
 *  | Context Buffer 1  | <--+-- | State Delta 1 |
 *  +---------+---------+    |   +---------------+
 *            |              |   +---------------+
 *            |              +-- | State Delta 2 |
 *            |                  +---------------+
 *            |
 *  +---------+---------+        +---------------+
 *  | Command Buffer 4  |  ....  | State Delta 3 |
 *  +---------+---------+        +---------------+
 *            |                    associations made:
 *            |                  +-------------------+        +---------------+
 *            |                  | Context Buffer 1  | -----> | State Delta 3 |
 *            |                  +-------------------+        +---------------+
 *            |                                               +---------------+
 *            |                                          +--> | State Delta 2 |
 *            |                  +-------------------+   |    +---------------+
 *            |                  | Context Buffer 2  | --+    +---------------+
 *            |                  +-------------------+   +--> | State Delta 3 |
 *            |                                               +---------------+
 *            |
 * ===========|=================================================================
 *            |
 */

#include "gc_hal.h"
#include "gc_hal_kernel.h"
#include "gc_hal_kernel_context.h"

/******************************************************************************
 ******************************* Debugging Macro ******************************
 ******************************************************************************/

/* Zone used for header/footer. */
#define _GC_OBJ_ZONE gcvZONE_HARDWARE

/******************************************************************************
 ************************** Context State Buffer Helpers **********************
 ******************************************************************************/

#define _STATE(reg)                                                            \
    _State(\
        Context, index, \
        reg ## _Address >> 2, \
        reg ## _ResetValue, \
        reg ## _Count, \
        gcvFALSE, gcvFALSE                                                     \
        )

#define _STATE_COUNT(reg, count)                                               \
    _State(\
        Context, index, \
        reg ## _Address >> 2, \
        reg ## _ResetValue, \
        count, \
        gcvFALSE, gcvFALSE                                                     \
        )

#define _STATE_COUNT_OFFSET(reg, offset, count)                                \
    _State(\
        Context, index, \
        (reg ## _Address >> 2) + (offset), \
        reg ## _ResetValue, \
        count, \
        gcvFALSE, gcvFALSE                                                     \
        )

#define _STATE_MIRROR_COUNT(reg, mirror, count)                                \
    _StateMirror(\
        Context, \
        reg ## _Address >> 2, \
        count, \
        mirror ## _Address >> 2                                                \
        )

#define _STATE_HINT(reg)                                                       \
    _State(\
        Context, index, \
        reg ## _Address >> 2, \
        reg ## _ResetValue, \
        reg ## _Count, \
        gcvFALSE, gcvTRUE                                                      \
        )

#define _STATE_HINT_BLOCK(reg, block, count)                                   \
    _State(\
        Context, index, \
        (reg ## _Address >> 2) + ((block) << reg ## _BLK), \
        reg ## _ResetValue, \
        count, \
        gcvFALSE, gcvTRUE                                                      \
        )

#define _STATE_COUNT_OFFSET_HINT(reg, offset, count)                           \
    _State(\
        Context, index, \
        (reg ## _Address >> 2) + (offset), \
        reg ## _ResetValue, \
        count, \
        gcvFALSE, gcvTRUE                                                      \
        )

#define _STATE_X(reg)                                                          \
    _State(\
        Context, index, \
        reg ## _Address >> 2, \
        reg ## _ResetValue, \
        reg ## _Count, \
        gcvTRUE, gcvFALSE                                                      \
        )

#define _STATE_INIT_VALUE(reg, value)                                          \
    _State(\
        Context, index, \
        reg ## _Address >> 2, \
        value, \
        reg ## _Count, \
        gcvFALSE, gcvFALSE                                                     \
        )

#define _STATE_INIT_VALUE_OFFSET(reg, offset, value)                           \
    _State(\
        Context, index, \
        (reg ## _Address >> 2) + (offset), \
        value, \
        1, \
        gcvFALSE, gcvFALSE                                                     \
        )

#define _STATE_INIT_VALUE_BLOCK(reg, value, block, count)                      \
    _State(\
        Context, index, \
        (reg ## _Address >> 2) + ((block) << reg ## _BLK), \
        value, \
        count, \
        gcvFALSE, gcvFALSE                                                     \
        )

#define _CLOSE_RANGE()                                                         \
    _TerminateStateBlock(Context, index)

#define _ENABLE(reg, field)                                                    \
    do {                                                                       \
        if (gcmVERIFYFIELDVALUE(data, reg, MASK_ ## field, ENABLED)) {         \
            enable |= gcmFIELDMASK(reg, field);                                \
        }                                                                      \
    } while (gcvFALSE)

#define _BLOCK_COUNT(reg) ((reg##_Count) >> (reg##_BLK))

/******************************************************************************
 *********************** Support Functions and Definitions ********************
 ******************************************************************************/

#define gcdSTATE_MASK \
    (gcmSETFIELDVALUE(0, AQ_COMMAND_NOP_COMMAND, OPCODE, NOP) | 0xC0FFEE)

#if gcdENABLE_SW_PREEMPTION
typedef struct {
    gctUINT inputBase;
    gctUINT count;
    gctUINT outputBase;
} gcsSTATEMIRROR;

const gcsSTATEMIRROR mirroredStates[] = {
    {0x5800, 0x300, 0x5B00},
    {0x5600, 0x100, 0x5700},
    {0xD800, 0x140, 0xD000},
};

gctUINT mirroredStatesCount;

static gceSTATUS
_ResetDelta(gcsSTATE_DELTA_PTR StateDelta)
{
    /* Not attached yet, advance the ID. */
    StateDelta->id += 1;

    /* Did ID overflow? */
    if (StateDelta->id == 0) {
        /* Reset the map to avoid erroneous ID matches. */
        gckOS_ZeroMemory(gcmUINT64_TO_PTR(StateDelta->mapEntryID), StateDelta->mapEntryIDSize);

        /* Increment the main ID to avoid matches after reset. */
        StateDelta->id += 1;
    }

    /* Reset the vertex element count. */
    StateDelta->elementCount = 0;

    /* Reset the record count. */
    StateDelta->recordCount = 0;

    /* Success. */
    return gcvSTATUS_OK;
}

static gceSTATUS
_DestroyDelta(gckCONTEXT Context, gcsSTATE_DELTA_PTR delta)
{
    gctUINT_PTR mapEntryIndex = gcmUINT64_TO_PTR(delta->mapEntryIndex);
    gctUINT_PTR mapEntryID = gcmUINT64_TO_PTR(delta->mapEntryID);
    gcsSTATE_DELTA_RECORD_PTR recordArray = gcmUINT64_TO_PTR(delta->recordArray);
    gceSTATUS status = gcvSTATUS_OK;

    gcmkHEADER();

    /* Free map index array. */
    if (mapEntryIndex != gcvNULL)
        gcmkONERROR(gcmkOS_SAFE_FREE(Context->os, mapEntryIndex));

    /* Allocate map ID array. */
    if (mapEntryID != gcvNULL)
        gcmkONERROR(gcmkOS_SAFE_FREE(Context->os, mapEntryID));

    /* Free state record array. */
    if (recordArray != gcvNULL)
        gcmkONERROR(gcmkOS_SAFE_FREE(Context->os, recordArray));

    gcmkONERROR(gcmkOS_SAFE_FREE(Context->os, delta));

OnError:

    /* Return the status. */
    gcmkFOOTER_NO();
    return gcvSTATUS_OK;
}

static gceSTATUS
_AllocateDelta(gckCONTEXT Context, gcsSTATE_DELTA_PTR *Delta)
{
    gckCONTEXT context = Context;
    gckOS os = context->os;
    gceSTATUS status;
    gcsSTATE_DELTA_PTR delta = gcvNULL;
    gctPOINTER pointer = gcvNULL;

    gcmkHEADER();

    if (context->maxState == 0) {
        *Delta = NULL;
        gcmkFOOTER_NO();
        return gcvSTATUS_OK;
    }

    /* Allocate the state delta structure. */
    gcmkONERROR(gckOS_Allocate(os, gcmSIZEOF(gcsSTATE_DELTA), (gctPOINTER *)&delta));

    /* Reset the context buffer structure. */
    gckOS_ZeroMemory(delta, gcmSIZEOF(gcsSTATE_DELTA));

    if (context->maxState > 0) {
        /* Compute UINT array size. */
        gctSIZE_T bytes = context->maxState * gcmSIZEOF(gctUINT);

        /* Allocate map ID array. */
        gcmkONERROR(gckOS_Allocate(os, bytes, &pointer));

        delta->mapEntryID = gcmPTR_TO_UINT64(pointer);

        /* Set the map ID size. */
        delta->mapEntryIDSize = (gctUINT32)bytes;

        /* Reset the record map. */
        gckOS_ZeroMemory(gcmUINT64_TO_PTR(delta->mapEntryID), bytes);

        /* Allocate map index array. */
        gcmkONERROR(gckOS_Allocate(os, bytes, &pointer));

        delta->mapEntryIndex = gcmPTR_TO_UINT64(pointer);
    }

    if (context->numStates > 0) {
        /* Allocate state record array. */
        gcmkONERROR(gckOS_Allocate(os,
                                   gcmSIZEOF(gcsSTATE_DELTA_RECORD) * context->numStates,
                                   &pointer));

        delta->recordArray = gcmPTR_TO_UINT64(pointer);
    }

    /* Reset the new state delta. */
    _ResetDelta(delta);

    *Delta = delta;

    gcmkFOOTER();
    return status;

OnError:
    if (delta)
        _DestroyDelta(Context, delta);

    gcmkFOOTER_NO();
    return status;
}
#endif

#if !gcdHARDWARE_CONTEXT_SWITCH
static gctUINT32
_TerminateStateBlock(gckCONTEXT Context, gctUINT32 Index)
{
    gctUINT32_PTR buffer;
    gctUINT32 align;

    /* Determine if we need alignment. */
    align = (Index & 1) ? 1 : 0;

    /* Address correct index. */
    buffer = (Context->buffer == gcvNULL) ? gcvNULL : Context->buffer->logical;

    /*
     * Flush the current state block; make sure no pairing with the states
     * to follow happens.
     */
    if (align && buffer != gcvNULL)
        buffer[Index] = 0xDEADDEAD;

    /* Reset last address. */
    Context->lastAddress = ~0U;

    /* Return alignment requirement. */
    return align;
}

static gctUINT32
_FlushPipe(gckCONTEXT Context, gctUINT32 Index, gcePIPE_SELECT Pipe)
{
    gctUINT32 flushSlots;
    gctBOOL txCacheFix;
    gctBOOL fcFlushStall;
    gctBOOL iCacheInvalidate;
    gctBOOL halti5;
    gctBOOL snapPages;
    gctBOOL hwTFB;
    gctBOOL blt;
    gctBOOL peTSFlush;
    gctBOOL multiCluster;
    gctBOOL computeOnly;

    txCacheFix = gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_TEX_CACHE_FLUSH_FIX);

    fcFlushStall = gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_FC_FLUSH_STALL);

    iCacheInvalidate = gckHARDWARE_IsFeatureAvailable(Context->hardware,
                                                      gcvFEATURE_SHADER_HAS_INSTRUCTION_CACHE);

    halti5 = gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_HALTI5);

    snapPages = gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_SNAPPAGE_CMD_FIX) &&
                    gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_SNAPPAGE_CMD);

    hwTFB = gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_HW_TFB);

    blt = gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_BLT_ENGINE);
    multiCluster = gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_MULTI_CLUSTER);

    peTSFlush = gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_PE_TILE_CACHE_FLUSH_FIX);

    computeOnly = gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_COMPUTE_ONLY);

    flushSlots = blt ? 10 : 6;

    if (Pipe == gcvPIPE_3D) {
        if (!txCacheFix) {
            /* Semaphore stall */
            flushSlots += blt ? 8 : 4;
        }

        /* VST cache */
        if (!computeOnly) {
            flushSlots += 2;
        }
    }

    if (fcFlushStall && !computeOnly) {
        /* Flush tile status cache. */
        flushSlots += blt ? ((!peTSFlush) ? 14 : 10) : 6;
    }

    if (iCacheInvalidate && !halti5)
        flushSlots += blt ? 16 : 12;

    if (hwTFB && !computeOnly)
        flushSlots += 2;

    /* Snap pages */
    if (snapPages)
        flushSlots += 2;

    if (Context->buffer != gcvNULL) {
        gctUINT32_PTR buffer;

        /* Address correct index. */
        buffer = Context->buffer->logical + Index;

        if (Pipe == gcvPIPE_3D && !txCacheFix) {
            if (blt) {
                /* Semaphore from FE to BLT. */
                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x502E) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E02) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x10 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

                /* Stall from FE to BLT. */
                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x09 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x10 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x502E) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));
            } else {
                /* Semaphore from FE to PE. */
                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E02) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x07 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

                /* Stall from FE to PE. */
                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x09 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x07 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));
            }
        }

        /* Flush the current pipe. */
        *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                         ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                         ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E03) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

        if (Pipe == gcvPIPE_2D) {
            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3)));
        } else {
            gctUINT32 flush = (computeOnly ? 0 :
                ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) |
                ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 1:1) - (0 ? 1:1) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:1) - (0 ? 1:1) + 1))))))) << (0 ? 1:1))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 1:1) - (0 ? 1:1) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:1) - (0 ? 1:1) + 1))))))) << (0 ? 1:1))) |
                ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 10:10) - (0 ? 10:10) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 10:10) - (0 ? 10:10) + 1))))))) << (0 ? 10:10))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 10:10) - (0 ? 10:10) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 10:10) - (0 ? 10:10) + 1))))))) << (0 ? 10:10))) |
                ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 11:11) - (0 ? 11:11) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 11:11) - (0 ? 11:11) + 1))))))) << (0 ? 11:11))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 11:11) - (0 ? 11:11) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 11:11) - (0 ? 11:11) + 1))))))) << (0 ? 11:11))) |
                (multiCluster ? 0 : ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 2:2) - (0 ? 2:2) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 2:2) - (0 ? 2:2) + 1))))))) << (0 ? 2:2))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 2:2) - (0 ? 2:2) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 2:2) - (0 ? 2:2) + 1))))))) << (0 ? 2:2)))))
                | ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5)));
            if (Context->hardware->identity.customerID == 0x59) {
                flush |= ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 2:2) - (0 ? 2:2) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 2:2) - (0 ? 2:2) + 1))))))) << (0 ? 2:2))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 2:2) - (0 ? 2:2) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 2:2) - (0 ? 2:2) + 1))))))) << (0 ? 2:2)))
                    /* | gcmSETFIELDVALUE(0, AQ_FLUSH, TL1_CACHE, ENABLE) */;
            }
            *buffer++ = flush;
        }

        if (hwTFB && !computeOnly) {
            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x7003) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)));

            *buffer++ = 0x1;
        }

        /* Flush VST in separate cmd. */
        if (Pipe == gcvPIPE_3D && !computeOnly) {
            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E03) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:4) - (0 ? 4:4) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:4) - (0 ? 4:4) + 1))))))) << (0 ? 4:4))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 4:4) - (0 ? 4:4) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:4) - (0 ? 4:4) + 1))))))) << (0 ? 4:4)));
        }

        /* Semaphore from FE to PE. */
        if (blt) {
            /* Semaphore from FE to BLT. */
            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x502E) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E02) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                        ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x10 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

            /* Stall from FE to BLT. */
            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x09 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                        ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x10 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x502E) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));
        } else {
            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E02) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                        ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x07 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

            /* Stall from FE to PE. */
            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x09 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                        ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x07 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));
        }

        if (fcFlushStall && !computeOnly) {
            if (!peTSFlush && blt) {
                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x502E) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x502B) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x502E) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));
            } else {
                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0594) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));
            }

            /* Semaphore from FE to PE. */
            if (blt) {
                /* Semaphore from FE to BLT. */
                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x502E) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E02) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x10 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

                /* Stall from FE to BLT. */
                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x09 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x10 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x502E) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));
            } else {
                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E02) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x07 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

                /* Stall from FE to PE. */
                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x09 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x07 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));
            }
        }

        if (iCacheInvalidate && !halti5) {
            /* Invalidate I$ after pipe is stalled */
            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0218) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x021A) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:4) - (0 ? 4:4) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:4) - (0 ? 4:4) + 1))))))) << (0 ? 4:4))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 4:4) - (0 ? 4:4) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:4) - (0 ? 4:4) + 1))))))) << (0 ? 4:4)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0218) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x021A) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5)));

            /* Semaphore from FE to PE. */
            if (blt) {
                /* Semaphore from FE to BLT. */
                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x502E) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E02) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x10 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

                /* Stall from FE to BLT. */
                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x09 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x10 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x502E) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));
            } else {
                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E02) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x07 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

                /* Stall from FE to PE. */
                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x09 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));

                *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x07 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));
            }
        }

        if (snapPages) {
            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x13 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                        ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                        ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x02 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                        ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x04 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                        ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x08 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                        ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x10 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0)));

            *buffer++ = 0;
        }
    }

    /* Number of slots taken by flushing pipe. */
    return flushSlots;
}

static gctUINT32
_SemaphoreStall(gckCONTEXT Context, gctUINT32 Index)
{
    gctBOOL blt = gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_BLT_ENGINE);

    if (Context->buffer != gcvNULL) {
        gctUINT32_PTR buffer;

        /* Address correct index. */
        buffer = Context->buffer->logical + Index;

        if (blt) {
            /* Semaphore from FE to BLT. */
            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x502E) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E02) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                        ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x10 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

            /* Stall from FE to BLT. */
            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x09 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                        ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x10 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x502E) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            *buffer = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 0:0) - (0 ? 0:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 0:0) - (0 ? 0:0) + 1))))))) << (0 ? 0:0)));
        } else {
            /* Semaphore from FE to PE. */
            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E02) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                        ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x07 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));

            /* Stall from FE to PE. */
            *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x09 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));

            *buffer   = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 4:0) - (0 ? 4:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:0) - (0 ? 4:0) + 1))))))) << (0 ? 4:0))) |
                        ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8))) | (((gctUINT32) (0x07 & ((gctUINT32) ((((1 ? 12:8) - (0 ? 12:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 12:8) - (0 ? 12:8) + 1))))))) << (0 ? 12:8)));
        }
    }

    /* Semaphore/stall takes 4 slots. */
    return (blt ? 8 : 4);
}

static gctUINT32
_SwitchPipe(gckCONTEXT Context, gctUINT32 Index, gcePIPE_SELECT Pipe)
{
    gctUINT32 slots = 2;

    if (Context->buffer != gcvNULL) {
        gctUINT32_PTR buffer;

        /* Address correct index. */
        buffer = Context->buffer->logical + Index;

        /* LoadState(AQPipeSelect, 1), pipe. */
        *buffer++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                         ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E00) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) |
                         ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)));

        *buffer = (Pipe == gcvPIPE_2D) ? 0x1 : 0x0;
    }

    Context->pipeSelectBytes = slots * gcmSIZEOF(gctUINT32);

    return slots;
}

static gctUINT32
_State(gckCONTEXT Context, gctUINT32 Index, gctUINT32 Address,
       gctUINT32 Value, gctUINT32 Size, gctBOOL FixedPoint, gctBOOL Hinted)
{
    gctUINT32_PTR buffer;
    gctUINT32 align;
    gctUINT32 i;

    /* Determine if we need alignment. */
    align = (Index & 1) ? 1 : 0;

    /* Address correct index. */
    buffer = (Context->buffer == gcvNULL) ? gcvNULL : Context->buffer->logical;

    if (buffer == gcvNULL && (Address + Size > Context->maxState)) {
        /* Determine maximum state. */
        Context->maxState = Address + Size;
    }

    if (buffer == gcvNULL) {
        /* Update number of states. */
        Context->numStates += Size;
    }

    /* Do we need a new entry? */
    if (Address != Context->lastAddress || FixedPoint != Context->lastFixed) {
        if (buffer != gcvNULL) {
            if (align) {
                /* Add filler. */
                buffer[Index++] = 0xDEADDEAD;
            }

            /* LoadState(Address, Count). */
            gcmkASSERT((Index & 1) == 0);

            if (FixedPoint) {
                buffer[Index] =
                    ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                    ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) |
                         ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (Size) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                         ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (Address) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));
            } else {
                buffer[Index] =
                    ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                    ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) |
                         ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (Size) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                         ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (Address) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));
            }

            /* Walk all the states. */
            for (i = 0; i < (gctUINT32)Size; i += 1) {
                /* Set state to uninitialized value. */
                buffer[Index + 1 + i] = Value;

                /* Set index in state mapping table. */
                Context->map[Address + i].index = (gctUINT)Index + 1 + i;
            }
        }

        /* Save information for this LoadState. */
        Context->lastIndex = (gctUINT)Index;
        Context->lastAddress = Address + Size;
        Context->lastSize = Size;
        Context->lastFixed = FixedPoint;

        /* Return size for load state. */
        return align + 1 + Size;
    }

    /* Append this state to the previous one. */
    if (buffer != gcvNULL) {
        /* Update last load state. */
        buffer[Context->lastIndex] = ((((gctUINT32) (buffer[Context->lastIndex])) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (Context->lastSize + Size) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)));

        /* Walk all the states. */
        for (i = 0; i < (gctUINT32)Size; i += 1) {
            /* Set state to uninitialized value. */
            buffer[Index + i] = Value;

            /* Set index in state mapping table. */
            Context->map[Address + i].index = (gctUINT)Index + i;
        }
    }

    /* Update last address and size. */
    Context->lastAddress += Size;
    Context->lastSize += Size;

    /* Return number of slots required. */
    return Size;
}

static gctUINT32
_StateMirror(gckCONTEXT Context, gctUINT32 Address,
             gctUINT32 Size, gctUINT32 AddressMirror)
{
    gctUINT32 i;

    /* Process when buffer is set. */
    if (Context->buffer != gcvNULL) {
        /* Walk all states. */
        for (i = 0; i < Size; i++) {
            /* Copy the mapping address. */
            Context->map[Address + i].index = Context->map[AddressMirror + i].index;
        }
    }

    /* Return the number of required maps. */
    return Size;
}

static void
_UpdateUnifiedReg(gckCONTEXT Context, gctUINT32 Address,
                  gctUINT32 Size, gctUINT32 Count)
{
    gctUINT base;
    gctUINT nopCount;
    gctUINT32_PTR nop;
    gcsCONTEXT_PTR buffer;
    gcsSTATE_MAP_PTR map;
    gctUINT i;

    /* Get the current context buffer. */
    buffer = Context->buffer;

    /* Get the state map. */
    map = Context->map;

    base = map[Address].index;

    if (Count > 1024) {
        buffer->logical[base - 1] =
            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) |
                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1024) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (Address) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

        buffer->logical[base + 1024 + 1] =
            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) |
                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (Count - 1024) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (Address + 1024) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

        /* Determine the number of NOP commands. */
        nopCount = (Size / 2) - (Count / 2);
        /* Determine the location of the first NOP. */
        nop = &buffer->logical[base + (Count | 1) + 2];

        /* Fill the unused space with NOPs. */
        for (i = 0; i < nopCount; i += 1) {
            if (nop >= buffer->logical + Context->totalSize)
                break;

            /* Generate a NOP command. */
            *nop = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x03 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));

            /* Advance. */
            nop += 2;
        }
    } else {
        buffer->logical[base - 1] =
            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) |
                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (Count) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) |
                 ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (Address) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

        /* Determine the number of NOP commands. */
        nopCount = (Size / 2) - (Count / 2) + Size / 1024;

        /* Determine the location of the first NOP. */
        nop = &buffer->logical[base + (Count | 1)];

        /* Fill the unused space with NOPs. */
        for (i = 0; i < nopCount; i += 1) {
            if (nop >= buffer->logical + Context->totalSize)
                break;

            /* Generate a NOP command. */
            *nop = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x03 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));

            /* Advance. */
            nop += 2;
        }
    }
}

static gceSTATUS
_InitializeNoShaderAndPixelEngine(gckCONTEXT Context)
{
    gctUINT32_PTR buffer;
    gctUINT32 index;

    gctBOOL halti5;
    gctBOOL hasSecurity;
    gctBOOL hasRobustness;
    gctBOOL multiCluster;
    gctUINT clusterAliveMask;

    gckHARDWARE hardware;

    gcmkHEADER();

    hardware = Context->hardware;

    gcmkVERIFY_OBJECT(hardware, gcvOBJ_HARDWARE);

    /* Reset the buffer index. */
    index = 0;

    /* Reset the last state address. */
    Context->lastAddress = ~0U;

    /* Get the buffer pointer. */
    buffer = (Context->buffer == gcvNULL) ? gcvNULL : Context->buffer->logical;

    /**************************************************************************/
    /* Build 3D states. *******************************************************/

    halti5 = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_HALTI5);
    hasSecurity = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SECURITY);
    hasRobustness = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_ROBUSTNESS);
    multiCluster = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_MULTI_CLUSTER);

    gckHARDWARE_QueryClusterInfo(hardware, &clusterAliveMask);

    /* Store the 3D entry index. */
    Context->entryOffset3D = (gctUINT)index * gcmSIZEOF(gctUINT32);

    /* Switch to 3D pipe. */
    index += _SwitchPipe(Context, index, gcvPIPE_3D);

    if (multiCluster) {
        index += _State(Context, index, (0x03920 >> 2) + (0 << 2), ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))) | (((gctUINT32) ((gctUINT32) (clusterAliveMask) & ((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))),
 4, gcvFALSE, gcvFALSE);

        if (hardware->kernel->device->coreNum > 4)
            index += _State(Context, index, (0x03990 >> 2) + (0 << 2), ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))) | (((gctUINT32) ((gctUINT32) (clusterAliveMask) & ((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))),
 4, gcvFALSE, gcvFALSE);

        index += _State(Context, index, (0x03910 >> 2) + (0 << 2), ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))) | (((gctUINT32) ((gctUINT32) (clusterAliveMask) & ((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))),
 4, gcvFALSE, gcvFALSE);

        if (hardware->kernel->device->coreNum > 4)
            index += _State(Context, index, (0x03980 >> 2) + (0 << 2), ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))) | (((gctUINT32) ((gctUINT32) (clusterAliveMask) & ((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))),
 4, gcvFALSE, gcvFALSE);

        index += _State(Context, index, 0x03908 >> 2, ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 2:0) - (0 ? 2:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 2:0) - (0 ? 2:0) + 1))))))) << (0 ? 2:0))) | (((gctUINT32) (0x2 & ((gctUINT32) ((((1 ? 2:0) - (0 ? 2:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 2:0) - (0 ? 2:0) + 1))))))) << (0 ? 2:0))),
 1, gcvFALSE, gcvFALSE);
    }

    /* Current context pointer. */
#if gcdDEBUG && 1
    index += _State(Context, index, 0x03850 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
#  endif

    index += _FlushPipe(Context, index, gcvPIPE_3D);

    /* Global states. */
    if (hasSecurity) {
        index += _State(Context, index, 0x03900 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _CLOSE_RANGE();
        index += _State(Context, index, 0x03904 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (halti5) {
        gctUINT32 uscControl = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 20:16) - (0 ? 20:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 20:16) - (0 ? 20:16) + 1))))))) << (0 ? 20:16))) | (((gctUINT32) ((gctUINT32) (2) & ((gctUINT32) ((((1 ? 20:16) - (0 ? 20:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 20:16) - (0 ? 20:16) + 1))))))) << (0 ? 20:16)));

        index += _State(Context, index, 0x03888 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x038C0 >> 2, 0x00000000, 16, gcvFALSE, gcvFALSE);

        uscControl |= ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 2:0) - (0 ? 2:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 2:0) - (0 ? 2:0) + 1))))))) << (0 ? 2:0))) | (((gctUINT32) ((gctUINT32) (hardware->options.uscL1CacheRatio) & ((gctUINT32) ((((1 ? 2:0) - (0 ? 2:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 2:0) - (0 ? 2:0) + 1))))))) << (0 ? 2:0)));
        if (multiCluster) {
            uscControl |= ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 11:8) - (0 ? 11:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 11:8) - (0 ? 11:8) + 1))))))) << (0 ? 11:8))) | (((gctUINT32) ((gctUINT32) (hardware->options.uscAttribCacheRatio) & ((gctUINT32) ((((1 ? 11:8) - (0 ? 11:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 11:8) - (0 ? 11:8) + 1))))))) << (0 ? 11:8)));
        }
        index += _State(Context, index, 0x03884 >> 2, uscControl, 1, gcvFALSE, gcvFALSE);
    } else {
        index += _State(Context, index, 0x03820 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x03828 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x0382C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x03834 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x03838 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x03854 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    index += _CLOSE_RANGE();

    /* Memory Controller */
    index += _State(Context, index, 0x01654 >> 2, 0x00200000, 1, gcvFALSE, gcvFALSE);

    if (hasSecurity || hasRobustness) {
         gctUINT32 mmuConfig = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 16:16) - (0 ? 16:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 16:16) - (0 ? 16:16) + 1))))))) << (0 ? 16:16))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 16:16) - (0 ? 16:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 16:16) - (0 ? 16:16) + 1))))))) << (0 ? 16:16)));

         if (!hardware->largeVAVersion)
             mmuConfig |= ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26)));

         index += _State(Context, index, 0x001AC >> 2, mmuConfig, 1, gcvFALSE, gcvFALSE);
    }

    /* Semaphore/stall. */
    index += _SemaphoreStall(Context, index);

    /**************************************************************************/
    /* Link to another address. ***********************************************/

    Context->linkIndex3D = (gctUINT)index;

    if (buffer != gcvNULL) {
        if (hardware->graphicsLargeVA) {
            buffer[index + 0] = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x17 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                     ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            buffer[index + 1] = 0;
            buffer[index + 2] = 0;
            buffer[index + 3] = 0;
        } else {
            buffer[index + 0] = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x08 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                     ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));
            buffer[index + 1] = 0;
        }
    }

    index += (hardware->graphicsLargeVA) ? 4 : 2;

    /* Store the end of the context buffer. */
    Context->bufferSize = index * gcmSIZEOF(gctUINT32);

    /**************************************************************************/
    /* Pipe switch for the case where neither 2D nor 3D are used. *************/

    /* Store the 3D entry index. */
    Context->entryOffsetXDFrom2D = (gctUINT)index * gcmSIZEOF(gctUINT32);

    /* Switch to 3D pipe. */
    index += _SwitchPipe(Context, index, gcvPIPE_3D);

    /* Store the location of the link. */
    Context->linkIndexXD = (gctUINT)index;

    if (buffer != gcvNULL) {
        if (hardware->graphicsLargeVA) {
            buffer[index + 0] = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x17 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                     ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            buffer[index + 1] = 0;
            buffer[index + 2] = 0;
            buffer[index + 3] = 0;
        } else {
            buffer[index + 0] = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x08 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                     ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));
            buffer[index + 1] = 0;
        }
    }

    index += (hardware->graphicsLargeVA) ? 4 : 2;

    /**************************************************************************/
    /* Save size for buffer. **************************************************/

    Context->totalSize = index * gcmSIZEOF(gctUINT32);

    /* Success. */
    gcmkFOOTER_NO();
    return gcvSTATUS_OK;
}

static gceSTATUS
_InitializeContextBuffer(gckCONTEXT Context)
{
    gctUINT32_PTR buffer = gcvNULL;
    gctUINT32 index;

    gctBOOL halti0, halti1, halti2, halti3, halti4, halti5;
    gctUINT i;
    gctUINT vertexUniforms, fragmentUniforms;
    gctBOOL unifiedUniform;
    gctBOOL hasGS, hasTS;
    gctBOOL bsupportAIGM;
    gctBOOL bSupportVSSemanticLoc;
    gctBOOL bSupportClipDis;
    gctBOOL genericAttrib;
    gctBOOL hasICache;
    gctBOOL hasICachePrefetch;
    gctUINT numRT = 0;
    gctUINT numSamplers = 32;
    gctBOOL hasTXdesc;
    gctBOOL hasSecurity;
    gctBOOL hasRobustness;
    gctBOOL multiCluster;
    gctBOOL smallBatch;
    gctBOOL raSmallBatch;
    gctBOOL multiCoreBlockSetCfg2;
    gctUINT clusterAliveMask[gcdMAX_MAJOR_CORE_COUNT];
    gctUINT gpuEnableMask = 0x1;
    gctBOOL hasPSCSThrottle;
    gctBOOL hasPerStageLocalStorage;
    gctBOOL hasMsaaFragOperation;
    gctBOOL newGPipe;
    gctBOOL computeOnly;
    gctBOOL bSupportHighpVecFormat;
    gctBOOL hasD3D11;
    gctBOOL hasProbe;
    gctBOOL hasGraphicVA40;
    gctBOOL hasVulkanFC;
#if gcdSYNC && gcdENDIAN_BIG
    gctUINT PEFenceEndianControl;
#  endif

    gckHARDWARE hardware;

    gcmkHEADER();

    hardware = Context->hardware;

    gcmkVERIFY_OBJECT(hardware, gcvOBJ_HARDWARE);

    if (!hardware->options.hasShader)
        return _InitializeNoShaderAndPixelEngine(Context);

    /* Reset the buffer index. */
    index = 0;

    /* Reset the last state address. */
    Context->lastAddress = ~0U;

    /* Get the buffer pointer. */
    buffer = (Context->buffer == gcvNULL) ? gcvNULL : Context->buffer->logical;

    /**************************************************************************/
    /* Build 3D states. *******************************************************/

    halti0 = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_HALTI0);
    halti1 = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_HALTI1);
    halti2 = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_HALTI2);
    halti3 = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_HALTI3);
    halti4 = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_HALTI4);
    halti5 = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_HALTI5);
    hasGS = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_GEOMETRY_SHADER);
    hasTS = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_TESSELLATION);
    bsupportAIGM = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SH_SUPPORT_AIGM);
    bSupportVSSemanticLoc = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SH_HAS_VS_SEMANTIC_LOC);
    bSupportClipDis = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SH_SUPPORT_CLIP_CULL_DISTANCE);
    genericAttrib = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_GENERIC_ATTRIB);
    hasICache = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SHADER_HAS_INSTRUCTION_CACHE);
    hasTXdesc = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_TX_DESCRIPTOR);
    hasSecurity = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SECURITY);
    hasRobustness = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_ROBUSTNESS);
    hasICachePrefetch = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SH_INSTRUCTION_PREFETCH);
    multiCluster = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_MULTI_CLUSTER);
    smallBatch = raSmallBatch = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SMALL_BATCH) &&
                                hardware->options.smallBatch;
    multiCoreBlockSetCfg2 = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_MULTI_CORE_BLOCK_SET_CONFIG2);
    hasPSCSThrottle = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_PSCS_THROTTLE);
    hasPerStageLocalStorage = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SH_PER_STAGE_LOCAL_STORAGE);
    hasMsaaFragOperation = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_MSAA_FRAGMENT_OPERATION);
    newGPipe = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_NEW_GPIPE);
    computeOnly = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_COMPUTE_ONLY);
    bSupportHighpVecFormat = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SH_SUPPORT_HIGHPVEC_FORMAT);
    hasD3D11 = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_D3D11_SUPPORT);
    hasProbe = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_PROBE);
    hasGraphicVA40 = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_MMU_40BIT_VA_GRAPHICS);
    hasVulkanFC = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_TS_FC_VULKAN_SUPPORT);

#if gcdFPGA_BUILD
    /* VIV_FILTER: CID=0x82 */
    if (hasD3D11 && smallBatch &&
        Context->hardware->identity.chipModel == gcv8800 && Context->hardware->identity.chipRevision == 0x7305 &&
        Context->hardware->identity.ecoID == 0x0 && Context->hardware->identity.customerID == 0x82)
        raSmallBatch = gcvFALSE;
    /* VIV_FILTER_END */

    /* VIV_FILTER: CID=0x72 */
    if (hasD3D11 && smallBatch &&
        Context->hardware->identity.chipModel == gcv8400 && Context->hardware->identity.chipRevision == 0x7305 &&
        Context->hardware->identity.ecoID == 0x0 && Context->hardware->identity.customerID == 0x72)
        raSmallBatch = gcvFALSE;
    /* VIV_FILTER_END */

    /* VIV_FILTER: CID=0x75 */
    if (hasD3D11 && smallBatch &&
        Context->hardware->identity.chipModel == gcv8400 && Context->hardware->identity.chipRevision == 0x7308 &&
        Context->hardware->identity.ecoID == 0x0 && Context->hardware->identity.customerID == 0x75)
        raSmallBatch = gcvFALSE;
    /* VIV_FILTER_END */
#endif

#if gcdSYNC && gcdENDIAN_BIG
    PEFenceEndianControl = gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_FENCE_64BIT) ?
                               0x3 :
                               0x2;
#  endif

    for (i = 0; i < gcdMAX_MAJOR_CORE_COUNT; i++)
        gckHARDWARE_QueryClusterInfo(hardware, &clusterAliveMask[i]);

    for (i = 0; i < hardware->kernel->device->coreNum; i++)
        gpuEnableMask |= 1 << i;

    /* Multi render target. */
    if (halti2)
        numRT = 8;
    else if (halti0)
        numRT = 4;
    else
        numRT = 1;

    if (hasGS && hasTS)
        numSamplers = 80;

    /* Query how many uniforms can support. */
    gcmCONFIGUREUNIFORMS2(Context->hardware->identity.chipModel,
                          Context->hardware->identity.chipRevision,
                          halti5, smallBatch, computeOnly,
                          Context->hardware->identity.numConstants,
                          unifiedUniform, vertexUniforms, fragmentUniforms);

#if !gcdENABLE_UNIFIED_CONSTANT
    if (Context->hardware->identity.numConstants > 256)
        unifiedUniform = gcvTRUE;
    else
        unifiedUniform = gcvFALSE;
#  endif

    /* Store the 3D entry index. */
    Context->entryOffset3D = (gctUINT)index * gcmSIZEOF(gctUINT32);

    /* Switch to 3D pipe. */
    index += _SwitchPipe(Context, index, gcvPIPE_3D);

    if (multiCluster) {
        i = (gctUINT)hardware->core;

        if (!hasD3D11) {
            index += _State(Context, index, 0x03920 >> 2, ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))) | (((gctUINT32) ((gctUINT32) (clusterAliveMask[i]) & ((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))),
 4, gcvFALSE, gcvFALSE);

            if (hardware->kernel->device->coreNum > 4)
                index += _State(Context, index, 0x03990 >> 2, ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))) | (((gctUINT32) ((gctUINT32) (clusterAliveMask[i]) & ((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))),
 4, gcvFALSE, gcvFALSE);
        }

        index += _State(Context, index, 0x03910 >> 2, ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))) | (((gctUINT32) ((gctUINT32) (clusterAliveMask[i]) & ((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))),
 4, gcvFALSE, gcvFALSE);

        if (hardware->kernel->device->coreNum > 4)
            index += _State(Context, index, 0x03980 >> 2, ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))) | (((gctUINT32) ((gctUINT32) (clusterAliveMask[i]) & ((gctUINT32) ((((1 ? 7:0) - (0 ? 7:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 7:0) - (0 ? 7:0) + 1))))))) << (0 ? 7:0))),
 4, gcvFALSE, gcvFALSE);

        index += _State(Context, index, 0x03908 >> 2, ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 2:0) - (0 ? 2:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 2:0) - (0 ? 2:0) + 1))))))) << (0 ? 2:0))) | (((gctUINT32) (0x2 & ((gctUINT32) ((((1 ? 2:0) - (0 ? 2:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 2:0) - (0 ? 2:0) + 1))))))) << (0 ? 2:0))),
 1, gcvFALSE, gcvFALSE);
    }

    /* Current context pointer. */
#if gcdDEBUG && 1
    index += _State(Context, index, 0x03850 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
#  endif

    index += _FlushPipe(Context, index, gcvPIPE_3D);

    /* Global states. */
    if (hasSecurity) {
        index += _State(Context, index, 0x03900 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _CLOSE_RANGE();
        index += _State(Context, index, 0x03904 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    index += _State(Context, index, 0x03814 >> 2, 0x00000001, 1, gcvFALSE, gcvFALSE);
    index += _CLOSE_RANGE();
    index += _State(Context, index, 0x03818 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    if (hasD3D11) {
        index += _State(Context, index, 0x039C4 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }
    index += _State(Context, index, 0x0381C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    if (halti5) {
        gctUINT32 uscControl = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 20:16) - (0 ? 20:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 20:16) - (0 ? 20:16) + 1))))))) << (0 ? 20:16))) | (((gctUINT32) ((gctUINT32) (2) & ((gctUINT32) ((((1 ? 20:16) - (0 ? 20:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 20:16) - (0 ? 20:16) + 1))))))) << (0 ? 20:16)));

        index += _State(Context, index, 0x03888 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x038C0 >> 2, 0x00000000, 16, gcvFALSE, gcvFALSE);

        uscControl |=
            ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 2:0) - (0 ? 2:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 2:0) - (0 ? 2:0) + 1))))))) << (0 ? 2:0))) | (((gctUINT32) ((gctUINT32) (hardware->options.uscL1CacheRatio) & ((gctUINT32) ((((1 ? 2:0) - (0 ? 2:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 2:0) - (0 ? 2:0) + 1))))))) << (0 ? 2:0)));
        if (multiCluster) {
            uscControl |= ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 11:8) - (0 ? 11:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 11:8) - (0 ? 11:8) + 1))))))) << (0 ? 11:8))) | (((gctUINT32) ((gctUINT32) (hardware->options.uscAttribCacheRatio) & ((gctUINT32) ((((1 ? 11:8) - (0 ? 11:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 11:8) - (0 ? 11:8) + 1))))))) << (0 ? 11:8)));
        }
        index += _State(Context, index, 0x03884 >> 2, uscControl, 1, gcvFALSE, gcvFALSE);
    } else {
        index += _State(Context, index, 0x03820 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x03828 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x0382C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x03834 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x03838 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x03854 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (bSupportClipDis) {
        index += _State(Context, index, 0x039B8 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x039BC >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x039B0 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x039B4 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00E38 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (hasGS)
        index += _State(Context, index, 0x0388C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    index += _State(Context, index, 0x0384C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    /* Front End states. */
    if (halti5) {
        index += _State(Context, index, 0x17800 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
        index += _CLOSE_RANGE();
        index += _State(Context, index, 0x007C4 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x007D0 >> 2, 0x00000000, 2, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x007D8 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x17A80 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
        if (genericAttrib || newGPipe) {
            index += _State(Context, index, 0x17880 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x17900 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x17980 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x17A00 >> 2, 0x3F800000, 32, gcvFALSE, gcvFALSE);
        }
    } else {
        index += _State(Context, index, 0x00600 >> 2, 0x00000000, (halti0 ? 16 : 12), gcvFALSE, gcvFALSE);
        index += _CLOSE_RANGE();
        if (genericAttrib) {
            index += _State(Context, index, 0x006C0 >> 2, 0x00000000, 16, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x00700 >> 2, 0x00000000, 16, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x00740 >> 2, 0x00000000, 16, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x00780 >> 2, 0x3F800000, 16, gcvFALSE, gcvFALSE);
        }
    }

    if (halti2 || Context->hardware->identity.streamCount > 8) {
        index += _State(Context, index, 0x14600 >> 2, 0x00000000, 16, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14640 >> 2, 0x00000000, 16, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14680 >> 2, 0x00000000, 16, gcvFALSE, gcvFALSE);
        if (hasD3D11) {
            index += _State(Context, index, 0x14700 >> 2, 0x00000000, 16, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x14740 >> 2, 0x00000000, 16, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x14780 >> 2, 0x00000000, 16, gcvFALSE, gcvFALSE);
        }
        if (hasGraphicVA40) {
            index += _State(Context, index, 0x1A080 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
        }
    } else if (Context->hardware->identity.streamCount > 1) {
        index += _State(Context, index, 0x00680 >> 2, 0x00000000, 8, gcvFALSE, gcvTRUE);
        index += _State(Context, index, 0x006A0 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);
    } else {
        index += _State(Context, index, 0x0064C >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        index += _State(Context, index, 0x00650 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }
    index += _State(Context, index, 0x00644 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
    if (hasGraphicVA40) {
        index += _State(Context, index, 0x00308 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }
    index += _State(Context, index, 0x00648 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00674 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    if (halti1) {
        index += _State(Context, index, 0x00678 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x0067C >> 2, 0xFFFFFFFF, 1, gcvFALSE, gcvFALSE);
    }

    index += _CLOSE_RANGE();

    if (hasRobustness) {
        index += _State(Context, index, 0x146C0 >> 2, 0x00000000, 16, gcvFALSE, gcvTRUE);
        index += _CLOSE_RANGE();
        index += _State(Context, index, 0x007F8 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        index += _CLOSE_RANGE();
        if (hasD3D11) {
            index += _State(Context, index, 0x147C0 >> 2, 0x00000000, 16, gcvFALSE, gcvTRUE);
            index += _CLOSE_RANGE();
        }
        if (hasGraphicVA40) {
            index += _State(Context, index, 0x1A100 >> 2, 0x00000000, 32, gcvFALSE, gcvTRUE);
            index += _CLOSE_RANGE();
            index += _State(Context, index, 0x0030C >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
            index += _CLOSE_RANGE();
        }
    }

    /* WD */
    if (multiCluster) {
        index += _State(Context, index, 0x18404 >> 2, ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))),
 1, gcvFALSE, gcvFALSE);
    }

    if (halti5) {
        index += _State(Context, index, 0x008B8 >> 2, ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:4) - (0 ? 4:4) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:4) - (0 ? 4:4) + 1))))))) << (0 ? 4:4))) | (((gctUINT32) ((gctUINT32) (smallBatch ? 0x0 : 0x1) & ((gctUINT32) ((((1 ? 4:4) - (0 ? 4:4) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:4) - (0 ? 4:4) + 1))))))) << (0 ? 4:4))) | ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) ((gctUINT32) (smallBatch ? 0x0 : 0x1) & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 8:8) - (0 ? 8:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 8:8) - (0 ? 8:8) + 1))))))) << (0 ? 8:8))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 8:8) - (0 ? 8:8) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 8:8) - (0 ? 8:8) + 1))))))) << (0 ? 8:8))) | ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 9:9) - (0 ? 9:9) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 9:9) - (0 ? 9:9) + 1))))))) << (0 ? 9:9))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 9:9) - (0 ? 9:9) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 9:9) - (0 ? 9:9) + 1))))))) << (0 ? 9:9))),
 1, gcvFALSE, gcvFALSE);

        index += _State(Context, index, 0x15600 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    } else {
        /*
         * This register is programed by all chips, which program all DECODE_SELECT as VS
         * except SAMPLER_DECODE_SELECT.
         */
        index += _State(Context, index, 0x00860 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (hasICache) {
        /* I-Cache states. */
        if (hasGraphicVA40) {
            index += _State(Context, index, 0x1563C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x010E8 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        }
        index += _State(Context, index, 0x00868 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x0086C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x0304C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x01028 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _CLOSE_RANGE();

        if (hasICachePrefetch) {
            if (halti5) {
                index += _State(Context, index, 0x15604 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
                index += _State(Context, index, 0x01094 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
            } else {
                index += _State(Context, index, 0x00890 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
                index += _State(Context, index, 0x0104C >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
            }
            index += _CLOSE_RANGE();
        }
    }

    if (multiCluster) {
        index += _State(Context, index, 0x010A8 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    /* Vertex Shader states. */
    index += _State(Context, index, 0x00804 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00808 >> 2, ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:0) - (0 ? 5:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:0) - (0 ? 5:0) + 1))))))) << (0 ? 5:0))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 5:0) - (0 ? 5:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:0) - (0 ? 5:0) + 1))))))) << (0 ? 5:0))),
 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x0080C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00830 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    if (halti5) {
        index += _State(Context, index, 0x00898 >> 2, 0x00000000, 2, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x008A0 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00870 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x008A8 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x008C0 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x008E0 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);
    } else {
        index += _State(Context, index, 0x00810 >> 2, 0x00000000, 4, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00820 >> 2, 0x00000000, 4, gcvFALSE, gcvFALSE);
    }

    if (multiCluster) {
        index += _State(Context, index, 0x007FC >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x15608 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (bsupportAIGM)
    {
        if (hasGraphicVA40)
        {
            index += _State(Context, index, 0x15638 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        }

        index += _State(Context, index, 0x15634 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (bSupportVSSemanticLoc)
    {
        index += _State(Context, index, 0x15640 >> 2, 0x0000007F, 1, gcvFALSE, gcvFALSE);
    }

    index += _CLOSE_RANGE();

    /* GS */
    if (hasGS) {
        index += _State(Context, index, 0x01100 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x01104 >> 2, 0x00000001, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x01108 >> 2, 0x01000001, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x0110C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x01110 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        if (hasGraphicVA40) {
            index += _State(Context, index, 0x01168 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        }
        index += _State(Context, index, 0x01114 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        index += _State(Context, index, 0x0111C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x01140 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x0115C >> 2, 0x000000FF, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x01144 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x01148 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x0114C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x01154 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x01120 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);

        if (bsupportAIGM)
        {
            if (hasGraphicVA40)
            {
                index += _State(Context, index, 0x01164 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            }

            index += _State(Context, index, 0x01160 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        }

        index += _CLOSE_RANGE();
    }

    /* TCS & TES */
    if (hasTS) {
        index += _State(Context, index, 0x007C0 >> 2, 0x00000003, 1, gcvFALSE, gcvFALSE);

        index += _State(Context, index, 0x14A14 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14A18 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14A1C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14A40 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14A00 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14A04 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        if (hasGraphicVA40) {
            index += _State(Context, index, 0x14A5C >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        }
        index += _State(Context, index, 0x14A08 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        index += _State(Context, index, 0x14A10 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14A20 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14A44 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14A4C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

        if (bsupportAIGM)
        {
            if (hasGraphicVA40)
            {
                index += _State(Context, index, 0x14A58 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            }

            index += _State(Context, index, 0x14A54 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        }

        index += _CLOSE_RANGE();

        index += _State(Context, index, 0x14B18 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14B1C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14B20 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14B04 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14B08 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        if (hasGraphicVA40) {
            index += _State(Context, index, 0x14B60 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        }
        index += _State(Context, index, 0x14B0C >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        index += _State(Context, index, 0x14B14 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14B40 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14B24 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14B2C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14B34 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

        if (bsupportAIGM)
        {
            if (hasGraphicVA40)
            {
                index += _State(Context, index, 0x14B3C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            }

            index += _State(Context, index, 0x14B38 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        }

        index += _State(Context, index, 0x14B00 >> 2, 0x00040000, 1, gcvFALSE, gcvFALSE);
    }

    index += _CLOSE_RANGE();

    /* TFB */
    if (gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_HW_TFB)) {
        if (hasGraphicVA40) {
            index += _State(Context, index, 0x1C018 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
            index += _State(Context, index, (0x1C140 >> 2) + ((0) << 4), 0x00000000, 4, gcvFALSE, gcvTRUE);
            index += _State(Context, index, 0x1C01C >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        }
        index += _State(Context, index, 0x1C000 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x1C008 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x1C040 >> 2) + ((0) << 4), 0x00000000, 4, gcvFALSE, gcvTRUE);
        index += _State(Context, index, 0x1C080 >> 2, 0x00000000, 4, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x1C0C0 >> 2, 0x00000000, 4, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x1C100 >> 2, 0x00000000, 4, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x1C800 >> 2, 0x00000000, 128 * 4, gcvFALSE, gcvFALSE);

        index += _State(Context, index, 0x1C014 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        index += _CLOSE_RANGE();

        if (hasD3D11) {
            index += _State(Context, index, 0x1C180 >> 2, 0x00000000, 4, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x1C1C0 >> 2, 0x00000000, 4, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x1C020 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        }
    }

    /* Primitive Assembly states. */
    if (hasD3D11)
    {
        index += _State(Context, index, 0x00A00 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00A04 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00A08 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00A0C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00A10 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00A14 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }
    else
    {
        index += _State(Context, index, 0x00A00 >> 2, 0x00000000, 1, gcvTRUE, gcvFALSE);
        index += _State(Context, index, 0x00A04 >> 2, 0x00000000, 1, gcvTRUE, gcvFALSE);
        index += _State(Context, index, 0x00A08 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00A0C >> 2, 0x00000000, 1, gcvTRUE, gcvFALSE);
        index += _State(Context, index, 0x00A10 >> 2, 0x00000000, 1, gcvTRUE, gcvFALSE);
        index += _State(Context, index, 0x00A14 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    index += _State(Context, index, 0x00A18 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00A1C >> 2, 0x3F000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00A28 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00A2C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00A30 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00A34 >> 2, 0x00002000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00A38 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00A3C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00A80 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00A84 >> 2, 0x00000000, 1, gcvTRUE, gcvFALSE);
    index += _State(Context, index, 0x00A8C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00A88 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    if (gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SH_SUPPORT_MULTIVIEWPORT)) {
        index += _State(Context, index, 0x1E800 >> 2, 0x00000000, 15, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x1E840 >> 2, 0x00000000, 15, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x1E880 >> 2, 0x00000000, 15, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x1E8C0 >> 2, 0x00000000, 15, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x1E900 >> 2, 0x00000000, 15, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x1E940 >> 2, 0x00000000, 15, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x1E980 >> 2, 0x00000000, 15, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x039C0 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (halti5) {
        index += _State(Context, index, 0x00AA8 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00A90 >> 2, 0x00000000, 4, gcvFALSE, gcvFALSE);
    } else {
        index += _State(Context, index, 0x00A40 >> 2, 0x00000000, Context->hardware->identity.varyingsCount, gcvFALSE, gcvFALSE);
    }

    if (hasD3D11) {
        index += _State(Context, index, 0x00AB0 >> 2, 0x00000040, 1, gcvFALSE, gcvFALSE);
    }

    if (multiCluster) {
        index += _State(Context, index, 0x00AAC >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    index += _State(Context, index, 0x03A00 >> 2, ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:28) - (0 ? 31:28) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:28) - (0 ? 31:28) + 1))))))) << (0 ? 31:28))) | (((gctUINT32) ((gctUINT32) (gpuEnableMask & 0xF) & ((gctUINT32) ((((1 ? 31:28) - (0 ? 31:28) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:28) - (0 ? 31:28) + 1))))))) << (0 ? 31:28))),
 1, gcvFALSE, gcvFALSE);

    if (hardware->kernel->device->coreNum > 4)
        index += _State(Context, index, 0x03A14 >> 2, ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) ((gpuEnableMask & 0xFFFF0) >> 4) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))),
 1, gcvFALSE, gcvFALSE);

    index += _State(Context, index, 0x03A04 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x03A08 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    if (multiCoreBlockSetCfg2) {
        index += _State(Context, index, 0x03A0C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x03A10 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    /* Setup states. */
    index += _State(Context, index, 0x00C00 >> 2, 0x00000000, 1, gcvTRUE, gcvFALSE);
    index += _State(Context, index, 0x00C04 >> 2, 0x00000000, 1, gcvTRUE, gcvFALSE);
    index += _State(Context, index, 0x00C08 >> 2, 0x45000000, 1, gcvTRUE, gcvFALSE);
    index += _State(Context, index, 0x00C0C >> 2, 0x45000000, 1, gcvTRUE, gcvFALSE);
    index += _State(Context, index, 0x00C10 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00C14 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00C18 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00C1C >> 2, 0x42000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00C20 >> 2, 0x00000000, 1, gcvTRUE, gcvFALSE);
    index += _State(Context, index, 0x00C24 >> 2, 0x00000000, 1, gcvTRUE, gcvFALSE);

    if (hasD3D11) {
        index += _State(Context, index, 0x00C28 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SH_SUPPORT_MULTIVIEWPORT)) {
        index += _State(Context, index, 0x00C40 >> 2, 0x00000000, 15, gcvTRUE, gcvFALSE);
        index += _State(Context, index, 0x00C80 >> 2, 0x00000000, 15, gcvTRUE, gcvFALSE);
        index += _State(Context, index, 0x00CC0 >> 2, 0x45000000, 15, gcvTRUE, gcvFALSE);
        index += _State(Context, index, 0x00D00 >> 2, 0x45000000, 15, gcvTRUE, gcvFALSE);
        index += _State(Context, index, 0x00D40 >> 2, 0x00000000, 15, gcvTRUE, gcvFALSE);
        index += _State(Context, index, 0x00D80 >> 2, 0x00000000, 15, gcvTRUE, gcvFALSE);
    }

    /* Raster states. */
    index += _State(Context, index, 0x00E00 >> 2, 0x000000F1, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00E10 >> 2, 0x00000000, 4, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00E04 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00E40 >> 2, 0x00000000, 16, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00E08 >> 2, ((((gctUINT32) (0x17800031)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 2:2) - (0 ? 2:2) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 2:2) - (0 ? 2:2) + 1))))))) << (0 ? 2:2))) | (((gctUINT32) ((gctUINT32) (raSmallBatch ? 0x0 : 0x1) & ((gctUINT32) ((((1 ? 2:2) - (0 ? 2:2) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 2:2) - (0 ? 2:2) + 1))))))) << (0 ? 2:2))),
 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00E24 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00E20 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    if (halti2)
        index += _State(Context, index, 0x00E0C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    if (halti5)
        index += _State(Context, index, 0x00E34 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    if (hasD3D11) {
        index += _State(Context, index, 0x00E3C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00E80 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    /* Pixel Shader states. */
    index += _State(Context, index, 0x01004 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01008 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x0100C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01010 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01030 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01034 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    if (halti2)
        index += _State(Context, index, 0x01040 >> 2, 0x00000000, 2, gcvFALSE, gcvFALSE);

    if (bSupportHighpVecFormat) {
        index += _State(Context, index, 0x010D4 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x010D8 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (numRT == 16) {
        index += _State(Context, index, 0x0102C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x010C8 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x010CC >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    } else if (numRT == 8) {
        index += _State(Context, index, 0x0102C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x01038 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (hasMsaaFragOperation) {
        index += _State(Context, index, 0x01054 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x01060 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);

        if (hasD3D11) {
            index += _State(Context, index, 0x010E4 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        }
    }

    if (halti5) {
        index += _State(Context, index, 0x01080 >> 2, 0x00000000, 4, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x01058 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x01098 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (hasPSCSThrottle)
    {
        index += _State(Context, index, 0x0109C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (hasPerStageLocalStorage)
    {
        index += _State(Context, index, 0x15620 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x15624 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x15628 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x1562C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x15630 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    index += _CLOSE_RANGE();

    /* Texture states. */
    if (hasTXdesc) {
        /* Texture descriptor states */
        index += _State(Context, index, 0x14C40 >> 2, 0x1, 1, gcvFALSE, gcvFALSE);

        if (!gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SH_SUPPORT_SEPARATED_TEX)) {

            if (smallBatch) {
                index += _State(Context, index, 0x010B0 >> 2, numSamplers, 1, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x010B4 >> 2, numSamplers, 1, gcvFALSE, gcvFALSE);

                index += _State(Context, index, 0x16000 >> 2, 0x00000000, numSamplers, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x16200 >> 2, 0x00000000, numSamplers, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x16400 >> 2, 0x00000000, numSamplers, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x16600 >> 2, 0x00000000, numSamplers, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x16800 >> 2, 0x00000000, numSamplers, gcvFALSE, gcvFALSE);

                index += _State(Context, index, (0x15800 >> 2) + ((0) << 0), 0x00000000, numSamplers, gcvFALSE, gcvTRUE);
                index += _State(Context, index, 0x15A00 >> 2, 0x00000000, numSamplers, gcvFALSE, gcvFALSE);

                index += _CLOSE_RANGE();
            }
            else {
                index += _State(Context, index, 0x16C00 >> 2, 0x00000000, numSamplers, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x16E00 >> 2, 0x00000000, numSamplers, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x17000 >> 2, 0x00000000, numSamplers, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x17200 >> 2, 0x00000000, numSamplers, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x17400 >> 2, 0x00000000, numSamplers, gcvFALSE, gcvFALSE);

                index += _State(Context, index, (0x15C00 >> 2) + ((0) << 0), 0x00000000, numSamplers, gcvFALSE, gcvTRUE);
                index += _State(Context, index, 0x15E00 >> 2, 0x00000000, numSamplers, gcvFALSE, gcvFALSE);

                index += _CLOSE_RANGE();

                _StateMirror(Context, 0x16000 >> 2, numSamplers , 0x16C00 >> 2);
                _StateMirror(Context, 0x16200 >> 2, numSamplers , 0x16E00 >> 2);
                _StateMirror(Context, 0x16400 >> 2, numSamplers , 0x17000 >> 2);
                _StateMirror(Context, 0x16600 >> 2, numSamplers , 0x17200 >> 2);
                _StateMirror(Context, 0x16800 >> 2, numSamplers , 0x17400 >> 2);
                _StateMirror(Context, 0x15800 >> 2, numSamplers , 0x15C00 >> 2);
                _StateMirror(Context, 0x15A00 >> 2, numSamplers , 0x15E00 >> 2);
            }
        }
        else {
            if (hasGraphicVA40){
                index += _State(Context, index, 0x14C74 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x14C7C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x1A200 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x14C6C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x14C70 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            }

            index += _State(Context, index, 0x14C4C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x14C54 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x14C64 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x14C68 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x14C58 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        }
    } else {
        index += _State(Context, index, 0x02000 >> 2, 0x00000000, 12, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x02040 >> 2, 0x00000000, 12, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x02080 >> 2, 0x00000000, 12, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x020C0 >> 2, 0x00000000, 12, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x02100 >> 2, 0x00000000, 12, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x02140 >> 2, 0x00000000, 12, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x02180 >> 2, 0x00000000, 12, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x021C0 >> 2, 0x00321000, 12, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x02200 >> 2, 0x00000000, 12, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x02240 >> 2, 0x00000000, 12, gcvFALSE, gcvFALSE);
        index += _State(Context, index, (0x02400 >> 2) + ((0) << 4), 0x00000000, 12, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x02440 >> 2) + ((0) << 4), 0x00000000, 12, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x02480 >> 2) + ((0) << 4), 0x00000000, 12, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x024C0 >> 2) + ((0) << 4), 0x00000000, 12, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x02500 >> 2) + ((0) << 4), 0x00000000, 12, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x02540 >> 2) + ((0) << 4), 0x00000000, 12, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x02580 >> 2) + ((0) << 4), 0x00000000, 12, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x025C0 >> 2) + ((0) << 4), 0x00000000, 12, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x02600 >> 2) + ((0) << 4), 0x00000000, 12, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x02640 >> 2) + ((0) << 4), 0x00000000, 12, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x02680 >> 2) + ((0) << 4), 0x00000000, 12, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x026C0 >> 2) + ((0) << 4), 0x00000000, 12, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x02700 >> 2) + ((0) << 4), 0x00000000, 12, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x02740 >> 2) + ((0) << 4), 0x00000000, 12, gcvFALSE, gcvTRUE);
        index += _CLOSE_RANGE();

        if (gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_TEXTURE_LINEAR)) {
            /*
             * Linear stride LODn will overwrite LOD0 on GC880,GC2000.
             * And only LOD0 is valid for this register.
             */
            gctUINT count = halti1 ? 14 : 1;

            for (i = 0; i < 12; i += 1)
                index += _State(Context, index, (0x02C00 >> 2) + i * 16, 0x00000000, count, gcvFALSE, gcvFALSE);
        }

        if (gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SUPPORT_GCREGTX)) {
            gctUINT texBlockCount;
            gctUINT gcregTXLogSizeResetValue;

            /*
             * Enable the integer filter pipe for all texture samplers
             * so that the floating point filter clock will shut off until
             * we start using the floating point filter.
             */
            gcregTXLogSizeResetValue = ((((gctUINT32) (0x00000000)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 29:29) - (0 ? 29:29) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 29:29) - (0 ? 29:29) + 1))))))) << (0 ? 29:29))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 29:29) - (0 ? 29:29) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 29:29) - (0 ? 29:29) + 1))))))) << (0 ? 29:29)));

            /* New texture block. */
            index += _State(Context, index, 0x10000 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x10080 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x10100 >> 2, gcregTXLogSizeResetValue, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x10180 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x10200 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x10280 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x10300 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x10380 >> 2, 0x00321000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x10400 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x10480 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);

            if (gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_TX_FILTER)) {
                index += _State(Context, index, 0x12000 >> 2, 0x00000000, 256, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x12400 >> 2, 0x00000000, 256, gcvFALSE, gcvFALSE);
            }

            texBlockCount = ((512) >> (4));

            for (i = 0; i < texBlockCount; i += 1)
                index += _State(Context, index, (0x10800 >> 2) + ((i) << 4), 0x00000000, 14, gcvFALSE, gcvTRUE);
        }

        if (gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_TEX_BASELOD))
            index += _State(Context, index, 0x10700 >> 2, 0x00000F00, 32, gcvFALSE, gcvFALSE);

        if (halti3 || gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_TX_SUPPORT_DEC))
            index += _State(Context, index, 0x10780 >> 2, 0x00030000, 32, gcvFALSE, gcvFALSE);

        if (halti4) {
            index += _State(Context, index, 0x11200 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x11280 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
        }

        if (gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_TX_FRAC_PRECISION_6BIT)) {
            index += _State(Context, index, 0x11000 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x11080 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x11100 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x11180 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x11300 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
        }

        /* ASTC */
        if (gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_TEXTURE_ASTC)) {
            index += _State(Context, index, 0x10500 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x10580 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x10600 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x10680 >> 2, 0x00000000, 32, gcvFALSE, gcvFALSE);
        }
    }

    if (halti3)
        index += _State(Context, index, 0x14C00 >> 2, 0x00000000, 16, gcvFALSE, gcvFALSE);

    /* Thread walker states. */
    index += _State(Context, index, 0x00900 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00904 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00908 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x0090C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00910 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00914 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00918 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x00924 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x0091C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    if (gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SHADER_ENHANCEMENTS2)) {
        index += _State(Context, index, 0x00940 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00944 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00948 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x0094C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00950 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00954 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (halti5) {
        index += _State(Context, index, 0x00958 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x0095C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00960 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    index += _CLOSE_RANGE();

    /* VS/PS Start/End PC register */
    if (halti5) {
        index += _State(Context, index, 0x00874 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x008BC >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x0087C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x01090 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _CLOSE_RANGE();
    } else if (hasICache) {
        /* New Shader instruction PC registers(20bit). */
        index += _State(Context, index, 0x00874 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00878 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x0087C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00880 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _CLOSE_RANGE();
    } else {
        if (Context->hardware->identity.instructionCount <= 256) {
            /* old shader instruction PC registers (12bit)*/
            index += _State(Context, index, 0x00800 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x00838 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            index += _CLOSE_RANGE();

            index += _State(Context, index, 0x01000 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x01018 >> 2, 0x01000000, 1, gcvFALSE, gcvFALSE);
            index += _CLOSE_RANGE();
        } else {
            /* New Shader instruction PC registers (16bit) */
            index += _State(Context, index, 0x0085C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x0101C >> 2, 0x00000100, 1, gcvFALSE, gcvFALSE);
            index += _CLOSE_RANGE();
        }
    }

    if (!hasICachePrefetch) {
        /* This unified one need SELECT bit to steer */
        if (Context->hardware->identity.instructionCount > 1024) {
            for (i = 0; i < Context->hardware->identity.instructionCount << 2; i += 256 << 2) {
                index += _State(Context, index, (0x20000 >> 2) + i, 0x00000000, 256 << 2, gcvFALSE, gcvFALSE);
                index += _CLOSE_RANGE();
            }
          /* This unified one is steered by base address, it's automatical. */
        } else if (Context->hardware->identity.instructionCount > 256) {
            /* VS instruction memory. */
            for (i = 0; i < Context->hardware->identity.instructionCount << 2; i += 256 << 2) {
                index += _State(Context, index, (0x0C000 >> 2) + i, 0x00000000, 256 << 2, gcvFALSE, gcvFALSE);
                index += _CLOSE_RANGE();
            }

            _StateMirror(Context, 0x08000 >> 2, Context->hardware->identity.instructionCount << 2 , 0x0C000 >> 2);
        } else { /* if (Context->hardware->identity.instructionCount <= 256).
                  * This is non-unified one.
                  */
            if (Context->hardware->identity.PSInstructionCount >
                Context->hardware->identity.instructionCount) {
                gcmkASSERT(Context->hardware->identity.PSInstructionCount % 256 == 0);

                /* We can support at most 1024 bytes for a single LOAD_STATE. */
                for (i = 0; i < Context->hardware->identity.PSInstructionCount << 2;
                     i += 256 << 2) {
                    index += _State(Context, index, (0x08000 >> 2) + i, 0x00000000, 256 << 2, gcvFALSE, gcvFALSE);
                    index += _CLOSE_RANGE();
                }
            } else {
                index += _State(Context, index, 0x06000 >> 2, 0x00000000, 1024, gcvFALSE, gcvFALSE);
                index += _CLOSE_RANGE();
            }

            index += _State(Context, index, 0x04000 >> 2, 0x00000000, 1024, gcvFALSE, gcvFALSE);
            index += _CLOSE_RANGE();
        }
    }

    if (unifiedUniform) {
        gctINT numConstants = Context->hardware->identity.numConstants;

        /* Base Offset register */
        index += _State(Context, index, 0x01024 >> 2, 0x00000100, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x00864 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _CLOSE_RANGE();

        if (smallBatch)
            index += _State(Context, index, 0x010AC >> 2, numConstants, 1, gcvFALSE, gcvFALSE);

        for (i = 0; numConstants > 0; i += 256 << 2, numConstants -= 256) {
            if (halti5) {
                if (numConstants >= 256) {
                    if (smallBatch)
                        index += _State(Context, index, (0x34000 >> 2) + i, 0x00000000, 256 << 2, gcvFALSE, gcvFALSE);
                    else
                        index += _State(Context, index, (0x36000 >> 2) + i, 0x00000000, 256 << 2, gcvFALSE, gcvFALSE);
                } else {
                    if (smallBatch)
                        index += _State(Context, index, (0x34000 >> 2) + i, 0x00000000, numConstants << 2, gcvFALSE, gcvFALSE);
                    else
                        index += _State(Context, index, (0x36000 >> 2) + i, 0x00000000, numConstants << 2, gcvFALSE, gcvFALSE);
                }
                index += _CLOSE_RANGE();
            } else {
                if (numConstants >= 256)
                    index += _State(Context, index, (0x30000 >> 2) + i, 0x00000000, 256 << 2, gcvFALSE, gcvFALSE);
                else
                    index += _State(Context, index, (0x30000 >> 2) + i, 0x00000000, numConstants << 2, gcvFALSE, gcvFALSE);

                index += _CLOSE_RANGE();
            }
        }

        if (halti5 && !smallBatch) {
            _StateMirror(Context, 0x34000 >> 2, Context->hardware->identity.numConstants << 2 , 0x36000 >> 2);
        }
    }
#if gcdENABLE_UNIFIED_CONSTANT
    else
#  endif
    {
        index += _State(Context, index, 0x05000 >> 2, 0x00000000, vertexUniforms * 4, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x07000 >> 2, 0x00000000, fragmentUniforms * 4, gcvFALSE, gcvFALSE);
    }

    if (halti1)
        index += _State(Context, index, 0x00884 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    if (halti5) {
        index += _State(Context, index, 0x008B0 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    /* Store the index of the "XD" entry. */
    Context->entryOffsetXDFrom3D = (gctUINT)index * gcmSIZEOF(gctUINT32);

    /* Pixel Engine states. */
    index += _State(Context, index, 0x01400 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01404 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01408 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x0140C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01414 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01418 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x0141C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01420 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01424 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01428 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x0142C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01434 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01454 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01458 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
    index += _State(Context, index, 0x014A0 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x014A8 >> 2, 0xFFFFFFFF, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x014AC >> 2, 0xFFFFFFFF, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01AFC >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    if (hasGraphicVA40) {
        index += _State(Context, index, 0x1EA64 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
    }

    if (gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_SH_SUPPORT_MULTIVIEWPORT)) {
        index += _State(Context, index, 0x1E9C0 >> 2, 0x00000000, 15, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x1EA00 >> 2, 0x00000000, 15, gcvFALSE, gcvFALSE);
    }

    if (gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_HALF_FLOAT_PIPE)) {
        index += _State(Context, index, 0x014B0 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x014B4 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (hasD3D11) {
        index += _State(Context, index, 0x014D8 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x17F40 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x17F60 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x17F80 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x17FA0 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);
    }

    index += _State(Context, index, 0x014A4 >> 2, 0x000E400C, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01580 >> 2, 0x00000000, 3, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x014B8 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    if (halti3)
        index += _State(Context, index, 0x0103C >> 2, 0x76543210, 1, gcvFALSE, gcvFALSE);

    if (hasGraphicVA40) {
        index += _State(Context, index, (0x1EB00 >> 2) + ((0) << 3), 0x00000000, Context->hardware->identity.pixelPipes, gcvFALSE, gcvTRUE);
    }

    index += _State(Context, index, (0x01460 >> 2) + ((0) << 3), 0x00000000, Context->hardware->identity.pixelPipes, gcvFALSE, gcvTRUE);

    if (Context->hardware->identity.pixelPipes == 1) {
        index += _State(Context, index, 0x01430 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        index += _State(Context, index, 0x01410 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
    }

    if (Context->hardware->identity.pixelPipes > 1 || halti0) {
        if (hasGraphicVA40) {
            index += _State(Context, index, (0x1EA40 >> 2) + ((0) << 3), 0x00000000, Context->hardware->identity.pixelPipes, gcvFALSE, gcvTRUE);
        }
        index += _State(Context, index, (0x01480 >> 2) + ((0) << 3), 0x00000000, Context->hardware->identity.pixelPipes, gcvFALSE, gcvTRUE);
    }

    for (i = 0; i < 3; i++) {
        index += _State(Context, index, (0x01500 >> 2) + ((i) << 3), 0x00000000, Context->hardware->identity.pixelPipes, gcvFALSE, gcvTRUE);
    }

    if (numRT == 16) {
        for (i = 0; i < 15; i++) {
            index += _State(Context, index, (0x17C00 >> 2) + ((i) << 0), 0x00000000, Context->hardware->identity.pixelPipes, gcvFALSE, gcvTRUE);
        }
        index += _State(Context, index, 0x17C40 >> 2, 0x00000000, 15, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x17C80 >> 2, 0x03012000, 15, gcvFALSE, gcvFALSE);
    } else if (numRT == 8) {
        for (i = 0; i < 7; i++) {
            if (hasGraphicVA40) {
                index += _State(Context, index, (0x1EB00 >> 2) + ((i + 1) << 3), 0x00000000, Context->hardware->identity.pixelPipes, gcvFALSE, gcvTRUE);
            }
            index += _State(Context, index, (0x14800 >> 2) + ((i) << 3), 0x00000000, Context->hardware->identity.pixelPipes, gcvFALSE, gcvTRUE);
        }
        index += _State(Context, index, 0x14900 >> 2, 0x00000000, 7, gcvFALSE, gcvFALSE);
    }

    if (halti3) {
#if gcdSYNC && gcdENDIAN_BIG
        index += _State(Context, index, 0x014BC >> 2, ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 10:9) - (0 ? 10:9) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 10:9) - (0 ? 10:9) + 1))))))) << (0 ? 10:9))) | (((gctUINT32) ((gctUINT32) (PEFenceEndianControl) & ((gctUINT32) ((((1 ? 10:9) - (0 ? 10:9) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 10:9) - (0 ? 10:9) + 1))))))) << (0 ? 10:9))),
 1, gcvFALSE, gcvFALSE);
#  else
        index += _State(Context, index, 0x014BC >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
#  endif
    }

    if (halti4)
        index += _State(Context, index, 0x014C0 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

    if (hasGS)
        index += _State(Context, index, 0x038A0 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);

    if (halti5) {
        index += _State(Context, index, 0x14920 >> 2, 0x00000000, 7, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14940 >> 2, 0x00000000, 7, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14960 >> 2, 0x00000000, 7, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x14980 >> 2, 0x00000000, 7, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x149A0 >> 2, 0x00000000, 7, gcvFALSE, gcvFALSE);
    }

    if (hasRobustness) {
        if (hasGraphicVA40) {
            index += _State(Context, index, 0x1EAC0 >> 2, 0x00000000, 8, gcvFALSE, gcvTRUE);
            index += _State(Context, index, 0x1EA60 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        }
        index += _State(Context, index, 0x149C0 >> 2, 0x00000000, 8, gcvFALSE, gcvTRUE);
        index += _State(Context, index, 0x014C4 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
    }

    /* Memory Controller */
    index += _State(Context, index, 0x01654 >> 2, 0x00200000, 1, gcvFALSE, gcvFALSE);

    if (hasD3D11) {
        index += _State(Context, index, 0x01AFC >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (hasGraphicVA40) {
        index += _State(Context, index, 0x1A4A0 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        index += _State(Context, index, 0x1A4A4 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
        index += _State(Context, index, 0x1A440 >> 2, 0x00000000, 8, gcvFALSE, gcvTRUE);
        index += _State(Context, index, 0x1A4A8 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
    }

    index += _CLOSE_RANGE();

    if (hasVulkanFC) {
        index += _State(Context, index, (0x017A0 >> 2) + 0, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    index += _State(Context, index, 0x01658 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
    index += _State(Context, index, 0x0165C >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
    index += _State(Context, index, 0x01660 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01664 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
    index += _State(Context, index, 0x01668 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
    index += _State(Context, index, 0x0166C >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01670 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01674 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x016A4 >> 2, 0x00000000, 1, gcvFALSE, gcvTRUE);
    index += _State(Context, index, 0x016AC >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x016A8 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01720 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);
    index += _State(Context, index, 0x01740 >> 2, 0x00000000, 8, gcvFALSE, gcvTRUE);
    index += _State(Context, index, 0x01760 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);

    if (halti2) {
        index += _State(Context, index, 0x01780 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);
        index += _State(Context, index, 0x016BC >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);

        if (hasVulkanFC && gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_BLT_ENGINE)) {
            index += _State(Context, index, 0x140B8 >> 2, 1, 1, gcvFALSE, gcvFALSE);
            if (hasGraphicVA40) {
                index += _State(Context, index, 0x18674 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
                index += _State(Context, index, 0x18678 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            }
            index += _State(Context, index, 0x14010 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x14020 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x140B8 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        }

        index += _State(Context, index, (0x017A0 >> 2) + 1, 0x00000000, 7, gcvFALSE, gcvFALSE);

        if (hasGraphicVA40) {
            index += _State(Context, index, 0x1A400 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);
            index += _State(Context, index, 0x1A420 >> 2, 0x00000000, 8, gcvFALSE, gcvFALSE);
        }

        index += _State(Context, index, (0x017C0 >> 2) + 1, 0x00000000, 7, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x017E0 >> 2) + 1, 0x00000000, 7, gcvFALSE, gcvTRUE);
        index += _State(Context, index, (0x01A00 >> 2) + 1, 0x00000000, 7, gcvFALSE, gcvFALSE);
        index += _State(Context, index, (0x01A20 >> 2) + 1, 0x00000000, 7, gcvFALSE, gcvFALSE);
        index += _State(Context, index, (0x01A40 >> 2) + 1, 0x00000000, 7, gcvFALSE, gcvFALSE);
    }

    index += _CLOSE_RANGE();

    if (gckHARDWARE_IsFeatureAvailable(hardware, gcvFEATURE_BUG_FIXES18)) {
        index += _State(Context, index, 0x03860 >> 2, 0x6, 1, gcvFALSE, gcvFALSE);
        index += _CLOSE_RANGE();
    }

    /* Probe */
    if (hasProbe) {
        index += _State(Context, index, 0x03870 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        if (hasGraphicVA40) {
            index += _State(Context, index, 0x1A6CC >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
        }
    }

    if (hasD3D11) {
        index += _State(Context, index, 0x039E0 >> 2, 0x00000000, 1, gcvFALSE, gcvFALSE);
    }

    if (halti3) {
        if (hasGraphicVA40) {
            index += _State(Context, index, 0x1A460 >> 2, 0x00000000, 8, gcvFALSE, gcvTRUE);
        }
        index += _State(Context, index, 0x01A80 >> 2, 0x00000000, 8, gcvFALSE, gcvTRUE);
        index += _CLOSE_RANGE();
    }

    if (hasSecurity || hasRobustness) {
         gctUINT32 mmuConfig = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 16:16) - (0 ? 16:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 16:16) - (0 ? 16:16) + 1))))))) << (0 ? 16:16))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 16:16) - (0 ? 16:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 16:16) - (0 ? 16:16) + 1))))))) << (0 ? 16:16)));

         if (!hardware->largeVAVersion)
             mmuConfig |= ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26)));

         index += _State(Context, index, 0x001AC >> 2, mmuConfig, 1, gcvFALSE, gcvFALSE);
    }

    /* Semaphore/stall. */
    index += _SemaphoreStall(Context, index);

    /**************************************************************************/
    /* Link to another address. ***********************************************/

    Context->linkIndex3D = (gctUINT)index;

    if (buffer != gcvNULL) {
        if (hardware->graphicsLargeVA) {
            buffer[index + 0] = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x17 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                     ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            buffer[index + 1] = 0;
            buffer[index + 2] = 0;
            buffer[index + 3] = 0;
        } else {
            buffer[index + 0] = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x08 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                     ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));
            buffer[index + 1] = 0;
        }
    }

    index += (hardware->graphicsLargeVA) ? 4 : 2;

    /* Store the end of the context buffer. */
    Context->bufferSize = index * gcmSIZEOF(gctUINT32);

    /**************************************************************************/
    /* Pipe switch for the case where neither 2D nor 3D are used. *************/

    /* Store the 3D entry index. */
    Context->entryOffsetXDFrom2D = (gctUINT)index * gcmSIZEOF(gctUINT32);

    /* Switch to 3D pipe. */
    index += _SwitchPipe(Context, index, gcvPIPE_3D);

    /* Store the location of the link. */
    Context->linkIndexXD = (gctUINT)index;

    if (buffer != gcvNULL) {
        if (hardware->graphicsLargeVA) {
            buffer[index + 0] = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x17 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                     ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

            buffer[index + 1] = 0;
            buffer[index + 2] = 0;
            buffer[index + 3] = 0;
        } else {
            buffer[index + 0] = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x08 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                                     ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));
            buffer[index + 1] = 0;
        }
    }

    index += (hardware->graphicsLargeVA) ? 4 : 2;


    /**************************************************************************/
    /* Save size for buffer. **************************************************/

    Context->totalSize = index * gcmSIZEOF(gctUINT32);

    /* Success. */
    gcmkFOOTER_NO();
    return gcvSTATUS_OK;
}
#endif /* !gcdHARDWARE_CONTEXT_SWITCH */

static gceSTATUS
_DestroyContext(gckCONTEXT Context)
{
    gceSTATUS status = gcvSTATUS_OK;
#if gcdCAPTURE_ONLY_MODE
    gceDATABASE_TYPE dbType;
    gctUINT32 processID;

    gcmkONERROR(gckOS_GetProcessID(&processID));
#endif

    if (Context != gcvNULL) {
        gcsCONTEXT_PTR bufferHead;

#if gcdENABLE_SW_PREEMPTION
        gcsSTATE_DELTA_PTR delta, next;

        /* Free state deltas. */
        for (Context->delta = Context->deltaHead; Context->delta != gcvNULL;) {
            delta = Context->delta;

            /* Get the next delta. */
            next = gcmUINT64_TO_PTR(delta->next);

            /* Last item? */
            if (next == Context->deltaHead)
                next = gcvNULL;

            _DestroyDelta(Context, delta);

            /* Remove from the list. */
            Context->delta = next;
        }

        gcmkVERIFY_OK(gckCONTEXT_DestroyPrevDelta(Context));
#endif

        /* Free context buffers. */
        for (bufferHead = Context->buffer; Context->buffer != gcvNULL;) {
            /* Get a shortcut to the current buffer. */
            gcsCONTEXT_PTR buffer = Context->buffer;

            /* Get the next buffer. */
            gcsCONTEXT_PTR next = buffer->next;

            /* Last item? */
            if (next == bufferHead)
                next = gcvNULL;

            /* Destroy the signal. */
            if (buffer->signal != gcvNULL) {
                gcmkONERROR(gckOS_DestroySignal(Context->os, buffer->signal));

                buffer->signal = gcvNULL;
            }

            /* Free state delta map. */
            if (buffer->logical != gcvNULL) {
                gckKERNEL kernel = Context->hardware->kernel;
                gckMMU mmu = gcvNULL;
                gctBOOL asynchronous = gcvTRUE;

                /* End cpu access. */
                gcmkVERIFY_OK(gckVIDMEM_NODE_UnlockCPU(kernel, buffer->videoMem,
                                                       0, gcvFALSE, gcvFALSE));

                gcmkONERROR(gckKERNEL_GetCurrentMMU(kernel, gcvTRUE, 0, &mmu));

                /* Synchronized unlock. */
                gcmkVERIFY_OK(gckVIDMEM_NODE_Unlock(kernel, buffer->videoMem, mmu, &asynchronous));

#if gcdCAPTURE_ONLY_MODE
                /* Encode surface type and pool to database type. */
                dbType = gcvDB_VIDEO_MEMORY |
                         (gcvVIDMEM_TYPE_GENERIC << gcdDB_VIDEO_MEMORY_TYPE_SHIFT) |
                         (buffer->videoMem->pool << gcdDB_VIDEO_MEMORY_POOL_SHIFT);

                gcmkONERROR(gckKERNEL_RemoveProcessDB(kernel, processID, dbType, buffer->videoMem));
#endif

                if (asynchronous) {
                    /* Free context buffer later. */
                    gcmkVERIFY_OK(gckEVENT_Unlock(kernel->eventObj,
                                             gcvKERNEL_PIXEL, mmu, buffer->videoMem));
                } else {
                    gcmkVERIFY_OK(gckVIDMEM_NODE_Dereference(kernel, buffer->videoMem));
                }

                buffer->logical = gcvNULL;
            }

            /* Free context buffer. */
            gcmkONERROR(gcmkOS_SAFE_FREE(Context->os, buffer));

            /* Remove from the list. */
            Context->buffer = next;
        }

        /* Mark the gckCONTEXT object as unknown. */
        Context->object.type = gcvOBJ_UNKNOWN;

        /* Free the gckCONTEXT object. */
        gcmkONERROR(gcmkOS_SAFE_FREE(Context->os, Context));
    }

OnError:
    return status;
}

static gceSTATUS
_AllocateContextBuffer(gckCONTEXT Context, gcsCONTEXT_PTR Buffer)
{
    gceSTATUS status;
    gckKERNEL kernel = Context->hardware->kernel;
    gcePOOL pool = gcvPOOL_DEFAULT;
    gctSIZE_T totalSize = Context->totalSize;
    gctUINT32 allocFlag = gcvALLOC_FLAG_FROM_USER;

#if gcdCAPTURE_ONLY_MODE
    gceDATABASE_TYPE dbType;
    gctUINT32        processID;
# endif

#if gcdENABLE_CACHEABLE_COMMAND_BUFFER
    allocFlag = gcvALLOC_FLAG_CACHEABLE;
# endif

    if (Context->hardware->largeVAVersion && !Context->hardware->graphicsLargeVA)
        allocFlag |= gcvALLOC_FLAG_32BIT_VA;

    /* Allocate video memory node for command buffers. */
    gcmkONERROR(gckKERNEL_AllocateVideoMemory(kernel, 64,
                                              gcvVIDMEM_TYPE_COMMAND, allocFlag,
                                              &totalSize, &pool, &Buffer->videoMem));

#if gcdCAPTURE_ONLY_MODE
    gcmkONERROR(gckVIDMEM_HANDLE_Allocate(kernel, Buffer->videoMem,
                                          &Context->buffer->handle));

    /* Encode surface type and pool to database type. */
    dbType = gcvDB_VIDEO_MEMORY |
             (gcvVIDMEM_TYPE_GENERIC << gcdDB_VIDEO_MEMORY_TYPE_SHIFT) |
             (pool << gcdDB_VIDEO_MEMORY_POOL_SHIFT);

    gcmkONERROR(gckOS_GetProcessID(&processID));

    /* Record in process db. */
    gcmkONERROR(gckKERNEL_AddProcessDB(kernel, processID, dbType,
                                       Buffer->videoMem, gcvNULL, totalSize));
# endif

    /* Lock for GPU access. */
    gcmkONERROR(gckVIDMEM_NODE_Lock(kernel, Buffer->videoMem, &Buffer->address));

    /* Lock for kernel side CPU access. */
    gcmkONERROR(gckVIDMEM_NODE_LockCPU(kernel, Buffer->videoMem,
                                       gcvFALSE, gcvFALSE,
                                       (gctPOINTER *)&Buffer->logical));

    return gcvSTATUS_OK;

OnError:
    return status;
}

/******************************************************************************
 **************************** Context Management API **************************
 ******************************************************************************/

/******************************************************************************\
 **
 **  gckCONTEXT_Construct
 **
 **  Construct a new gckCONTEXT object.
 **
 **  INPUT:
 **
 **      gckOS Os
 **          Pointer to gckOS object.
 **
 **      gctUINT32 ProcessID
 **          Current process ID.
 **
 **      gckHARDWARE Hardware
 **          Pointer to gckHARDWARE object.
 **
 **  OUTPUT:
 **
 **      gckCONTEXT *Context
 **          Pointer to a variable thet will receive the gckCONTEXT object
 **          pointer.
 */

#if gcdHARDWARE_CONTEXT_SWITCH
gceSTATUS
gckCONTEXT_Construct(gckOS Os, gckHARDWARE Hardware,
    gctUINT32 ProcessID, gctBOOL Shared, gckCONTEXT *Context)
{
    gceSTATUS status = gcvSTATUS_OK;
    gckCONTEXT context = gcvNULL;
    gctUINT32 allocationSize;
    gctPOINTER pointer = gcvNULL;
    gckCOMMAND command = gcvNULL;
    gcsCONTEXT_PTR buffer = gcvNULL;
    gcsCONTEXT_PTR probeBuffer = gcvNULL;

    gcmkHEADER_ARG("Os=%p Hardware=%p", Os, Hardware);

    /* Verify the arguments. */
    gcmkVERIFY_OBJECT(Os, gcvOBJ_OS);
    gcmkVERIFY_ARGUMENT(Context != gcvNULL);

    /**************************************************************************/
    /************** Allocate and initialize struct gckCONTEXT. ****************/

    /* The context object size. */
    allocationSize = gcmSIZEOF(struct _gckCONTEXT);

    /* Allocate the object. */
    gcmkONERROR(gckOS_Allocate(Os, allocationSize, &pointer));

    context = pointer;

    /* Reset the entire object. */
    gcmkONERROR(gckOS_ZeroMemory(context, allocationSize));

    /* Initialize the gckCONTEXT object. */
    context->object.type = gcvOBJ_CONTEXT;
    context->os = Os;
    context->hardware = Hardware;
    context->needInitialize = gcvTRUE;

    /* context state buffer size */
    context->totalSize = 16 * 1024;
    /* Add for stateDelta != null */
    context->maxState = 64 * 1024;
    /* Add for recordArray != null */
    context->numStates = 3 * 1024;

    command = context->hardware->kernel->command;

    /* In gc_hal_kernel_hardware.c : 5809        */
    /*    if (GpuProfiler == gcvTRUE)            */
    /*        Hardware->waitCount = 200 * 100;   */
    if (Hardware->waitCount == 200 * 100)
        context->probeEnabled = gcvTRUE;
    else
        context->probeEnabled = gcvFALSE;

#if gcdSHARED_COMMAND_BUFFER
    if (Shared)
        command = context->hardware->kernel->sharedCommand;
# endif

    /**************************************************************************/
    /***************** Allocate and initialize state buffer *******************/

    /* Allocate the state buffer structure. */
    gcmkONERROR(gckOS_Allocate(Os, gcmSIZEOF(gcsCONTEXT), &pointer));
    buffer = pointer;

    /* Reset the context buffer structure. */
    gcmkVERIFY_OK(gckOS_ZeroMemory(buffer, gcmSIZEOF(gcsCONTEXT)));

    /* Create and set the signal, buffer is currently not busy. */
    gcmkONERROR(gckOS_CreateSignal(Os, gcvFALSE, &buffer->signal));
    gcmkONERROR(gckOS_Signal(Os, buffer->signal, gcvTRUE));

    /* Create physical buffer. */
    gcmkONERROR(_AllocateContextBuffer(context, buffer));

    /* Set gckEVENT object pointer. */
    buffer->eventObj = Hardware->kernel->eventObj;

    context->buffer = buffer;

    /**************************************************************************/
    /***************** Allocate and initialize probe buffer *******************/
    if (context->probeEnabled == gcvTRUE) {
        /* context probe buffer size */
        context->totalSize = 3325 * 4 * 8;

        /* Allocate the probe buffer structure. */
        gcmkONERROR(gckOS_Allocate(Os, gcmSIZEOF(gcsCONTEXT), &pointer));
        probeBuffer = pointer;

        /* Reset the context buffer structure. */
        gcmkVERIFY_OK(gckOS_ZeroMemory(probeBuffer, gcmSIZEOF(gcsCONTEXT)));

        /* Create and set the signal, buffer is currently not busy. */
        gcmkONERROR(gckOS_CreateSignal(Os, gcvFALSE, &probeBuffer->signal));
        gcmkONERROR(gckOS_Signal(Os, probeBuffer->signal, gcvTRUE));

        /* Create physical buffer. */
        gcmkONERROR(_AllocateContextBuffer(context, probeBuffer));

        /* Set gckEVENT object pointer. */
        probeBuffer->eventObj = Hardware->kernel->eventObj;
    }
    context->probeBuffer = probeBuffer;

    /* Return pointer to the gckCONTEXT object. */
    *Context = context;

    /* Success. */
    gcmkFOOTER_ARG("*Context=%p", *Context);
    return gcvSTATUS_OK;

OnError:
    /* Roll back on error. */
    gcmkVERIFY_OK(_DestroyContext(context));

    /* Return the status. */
    gcmkFOOTER();
    return status;
}

gceSTATUS
gckCONTEXT_MapBuffer(gckCONTEXT Context, gctUINT64 *Logicals, gctUINT32 *Bytes)
{
    gceSTATUS status;
    int i = 0;
    gckKERNEL kernel = Context->hardware->kernel;
    gctPOINTER logical;
    gcsCONTEXT_PTR buffer;

    gcmkHEADER_ARG("Context=%p", Context);

    buffer = Context->buffer;

    /* Lock for userspace CPU access. */
    gcmkONERROR(gckVIDMEM_NODE_LockCPU(kernel, buffer->videoMem,
                                           gcvFALSE, gcvTRUE, &logical));

    Logicals[i] = gcmPTR_TO_UINT64(logical);

    *Bytes = (gctUINT)Context->totalSize;

    gcmkFOOTER_NO();
    return gcvSTATUS_OK;

OnError:
    gcmkFOOTER();
    return status;
}

/******************************************************************************\
 **
 **  gckCONTEXT_Destroy
 **
 **  Destroy a gckCONTEXT object.
 **
 **  INPUT:
 **
 **      gckCONTEXT Context
 **          Pointer to an gckCONTEXT object.
 **
 **  OUTPUT:
 **
 **      Nothing.
 */
gceSTATUS
gckCONTEXT_Destroy(gckCONTEXT Context)
{
    gceSTATUS status;
    gctUINT32 processID;
    gcsCONTEXT_PTR buffer;
    gcsCONTEXT_PTR probeBuffer;

    gcmkHEADER_ARG("Context=%p", Context);

    /* Verify the arguments. */
    gcmkVERIFY_OBJECT(Context, gcvOBJ_CONTEXT);

    gcmkONERROR(gckOS_GetProcessID(&processID));

    /* Destroy the context and all related objects. */
    if (Context != gcvNULL) {
        /* Wait fence from hardware or CModel */
        gcmkONERROR(gckCONTEXT_HWSwitchCheckFence(Context, processID));

    /**************************************************************************/
    /*************************** Free state buffer ****************************/
        buffer = Context->buffer;

        /* Destroy the signal. */
        if (buffer->signal != gcvNULL) {
            gcmkONERROR(gckOS_DestroySignal(Context->os, buffer->signal));
            buffer->signal = gcvNULL;
        }

        if (buffer->logical != gcvNULL) {
            gckKERNEL kernel = Context->hardware->kernel;
            gckMMU mmu = gcvNULL;

#if gcdCAPTURE_ONLY_MODE
            gceDATABASE_TYPE dbType;
#endif
            /* End cpu access. */
            gcmkVERIFY_OK(gckVIDMEM_NODE_UnlockCPU(kernel, buffer->videoMem,
                0, gcvFALSE, gcvFALSE));

            gcmkONERROR(gckKERNEL_GetCurrentMMU(kernel, gcvTRUE, 0, &mmu));

            /* Synchronized unlock. */
            gcmkVERIFY_OK(gckVIDMEM_NODE_Unlock(kernel, buffer->videoMem, mmu, gcvNULL));

#if gcdCAPTURE_ONLY_MODE
            /* Encode surface type and pool to database type. */
            dbType = gcvDB_VIDEO_MEMORY |
                (gcvVIDMEM_TYPE_GENERIC << gcdDB_VIDEO_MEMORY_TYPE_SHIFT) |
                (buffer->videoMem->pool << gcdDB_VIDEO_MEMORY_POOL_SHIFT);

            gcmkONERROR(gckKERNEL_RemoveProcessDB(kernel, processID, dbType, buffer->videoMem));
#endif

            gcmkVERIFY_OK(gckVIDMEM_NODE_Dereference(kernel, buffer->videoMem));

            buffer->logical = gcvNULL;
        }

        /* Free state buffer memory */
        gcmkONERROR(gcmkOS_SAFE_FREE(Context->os, buffer));

        /**************************************************************************/
        /*************************** Free probe buffer ****************************/
        probeBuffer = Context->probeBuffer;
        if (probeBuffer != gcvNULL) {
            /* Destroy the signal. */
            if (probeBuffer->signal != gcvNULL) {
                gcmkONERROR(gckOS_DestroySignal(Context->os, probeBuffer->signal));
                probeBuffer->signal = gcvNULL;
            }

            if (probeBuffer->logical != gcvNULL) {
                gckKERNEL kernel = Context->hardware->kernel;
                gckMMU mmu = gcvNULL;

#if gcdCAPTURE_ONLY_MODE
                gceDATABASE_TYPE dbType;
#endif
                /* End cpu access. */
                gcmkVERIFY_OK(gckVIDMEM_NODE_UnlockCPU(kernel, probeBuffer->videoMem,
                    0, gcvFALSE, gcvFALSE));

                gcmkONERROR(gckKERNEL_GetCurrentMMU(kernel, gcvTRUE, 0, &mmu));

                /* Synchronized unlock. */
                gcmkVERIFY_OK(gckVIDMEM_NODE_Unlock(kernel, probeBuffer->videoMem, mmu, gcvNULL));

#if gcdCAPTURE_ONLY_MODE
                /* Encode surface type and pool to database type. */
                dbType = gcvDB_VIDEO_MEMORY |
                    (gcvVIDMEM_TYPE_GENERIC << gcdDB_VIDEO_MEMORY_TYPE_SHIFT) |
                    (buffer->videoMem->pool << gcdDB_VIDEO_MEMORY_POOL_SHIFT);

                gcmkONERROR(gckKERNEL_RemoveProcessDB(kernel, processID, dbType, buffer->videoMem));
#endif

                gcmkVERIFY_OK(gckVIDMEM_NODE_Dereference(kernel, probeBuffer->videoMem));

                probeBuffer->logical = gcvNULL;
            }

            /* Free probe buffer memory */
            gcmkONERROR(gcmkOS_SAFE_FREE(Context->os, probeBuffer));

        }

        /* Mark the gckCONTEXT object as unknown. */
        Context->object.type = gcvOBJ_UNKNOWN;

        /* Free the gckCONTEXT object. */
        gcmkONERROR(gcmkOS_SAFE_FREE(Context->os, Context));
    }

    /* Success. */
    gcmkFOOTER_NO();
    return gcvSTATUS_OK;

OnError:
    return status;
}

gceSTATUS
gckCONTEXT_HWSwitchWriteCommand(gckHARDWARE Hardware,
    gckCONTEXT Context,
    gctPOINTER Logical,
    gctBOOL SwitchMMU,
    gctBOOL SwitchProbe,
    gceCONTEXT_SWITCH_OPERATION Operation,
    gctUINT32 *Bytes)
{
    /* local var */
    gceSTATUS status;
    gctUINT32_PTR logical = gcvNULL;
    gctADDRESS ctxbufAddress = 0x0;
    gctADDRESS probebufAddress = 0x0;
    gctUINT32 pageTableID = 0x0;
    gctUINT32 ctxbufAddressLow32 = 0x0;
    gctUINT32 ctxbufAddressHigh32 = 0x0;
    gctUINT32 probebufAddressLow32 = 0x0;
    gctUINT32 probebufAddressHigh32 = 0x0;
    gctUINT32 bytes;

    gcmkHEADER_ARG("Hardware=0x%x Context=0x%x Logical=0x%x", Hardware, Context, Logical);

    /* Verify the arguments */
    gcmkVERIFY_OBJECT(Hardware, gcvOBJ_HARDWARE);

    /* size of this command */
    bytes = 6 * 4;

    /* values used to write */
    logical = (gctUINT32_PTR)Logical;

    if (Context != gcvNULL) {
        gcmkSAFECASTVA(ctxbufAddress, Context->buffer->address);
        ctxbufAddressLow32 = (gctUINT32)((ctxbufAddress << 32) >> 32);
        ctxbufAddressHigh32 = (gctUINT32)(ctxbufAddress >> 32);

        if (SwitchProbe) {
            gcmkSAFECASTVA(probebufAddress, Context->probeBuffer->address);
            probebufAddressLow32 = (gctUINT32)((probebufAddress << 32) >> 32);
            probebufAddressHigh32 = (gctUINT32)(probebufAddress >> 32);
        }

        pageTableID = Hardware->kernel->mmu->descIndex;
    }


    /* write */
    if (logical != gcvNULL) {
        switch (Operation) {
        case(gcvCONTEXT_RESTORE):
            if (SwitchMMU && SwitchProbe)
                *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) |
                                  ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) | (((gctUINT32) ((gctUINT32) (pageTableID) & ((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x1C & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));
            else if (SwitchMMU && !SwitchProbe)
                *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) |
                                  ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) | (((gctUINT32) ((gctUINT32) (pageTableID) & ((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x1C & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));
            else if (!SwitchMMU && SwitchProbe)
                *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) |
                                  ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) | (((gctUINT32) ((gctUINT32) (pageTableID) & ((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x1C & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));
            else
                *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) |
                                  ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) | (((gctUINT32) ((gctUINT32) (pageTableID) & ((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x1C & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));
            break;

        case(gcvCONTEXT_SAVE):
            if (SwitchMMU && SwitchProbe)
                *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) | (((gctUINT32) (0x2 & ((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) |
                                  ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) | (((gctUINT32) ((gctUINT32) (pageTableID) & ((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x1C & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));
            else if (SwitchMMU && !SwitchProbe)
                *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) | (((gctUINT32) (0x2 & ((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) |
                                  ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) | (((gctUINT32) ((gctUINT32) (pageTableID) & ((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x1C & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));
            else if (!SwitchMMU && SwitchProbe)
                *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) | (((gctUINT32) (0x2 & ((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) |
                                  ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) | (((gctUINT32) ((gctUINT32) (pageTableID) & ((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x1C & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));
            else
                *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) | (((gctUINT32) (0x2 & ((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) |
                                  ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) | (((gctUINT32) ((gctUINT32) (pageTableID) & ((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x1C & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));
            break;

        case(gcvCONTEXT_INIT):
            if (SwitchMMU && SwitchProbe)
                *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) |
                                  ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) | (((gctUINT32) ((gctUINT32) (pageTableID) & ((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x1C & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));
            else if (SwitchMMU && !SwitchProbe)
                *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) |
                                  ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) | (((gctUINT32) ((gctUINT32) (pageTableID) & ((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x1C & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));
            else if (!SwitchMMU && SwitchProbe)
                *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x1 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) |
                                  ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) | (((gctUINT32) ((gctUINT32) (pageTableID) & ((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x1C & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));
            else
                *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 1:0) - (0 ? 1:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 1:0) - (0 ? 1:0) + 1))))))) << (0 ? 1:0))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 3:3) - (0 ? 3:3) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 3:3) - (0 ? 3:3) + 1))))))) << (0 ? 3:3))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) |
                                  ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) | (((gctUINT32) ((gctUINT32) (pageTableID) & ((gctUINT32) ((((1 ? 22:7) - (0 ? 22:7) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 22:7) - (0 ? 22:7) + 1))))))) << (0 ? 22:7))) |
                             ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x1C & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));


            break;

        default:
            gcmkONERROR(gcvSTATUS_INVALID_ARGUMENT);
            break;
        }

        *logical++ = ctxbufAddressLow32;

        *logical++ = ctxbufAddressHigh32;

        *logical++ = probebufAddressLow32;

        *logical++ = probebufAddressHigh32;

        *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x03 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));
    }

    /* Bytes query */
    if (Bytes != gcvNULL)
        *Bytes = bytes;

    /* success */
    gcmkFOOTER_ARG("*Byte=0x%x", gcmOPT_VALUE(Bytes));
    return gcvSTATUS_OK;

OnError:
    gcmkFOOTER();
    return status;
}

gceSTATUS
gckCONTEXT_HWSwitchAddFence(gckHARDWARE Hardware, gctPOINTER Logical,
                                gctADDRESS FenceAddress, gctUINT64 FenceData, gctUINT32 *Bytes)
{
    gctUINT32_PTR logical = (gctUINT32_PTR)Logical;
    gctUINT32 dataLow = (gctUINT32)FenceData;
    gctUINT32 dataHigh = (gctUINT32)(FenceData >> 32);

    if (logical) {
        gctUINT32 fenceAddress;

        gcmkSAFECASTVA(fenceAddress, FenceAddress);
        if (Hardware->graphicsLargeVA) {
            *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                              ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E75) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) |
                              ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)));

            *logical++ = (gctUINT32)(FenceAddress >> 32);
        }

        *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                          ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E1A) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) |
                          ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)));

        *logical++ = fenceAddress;

        *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                          ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E26) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) |
                          ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)));

        *logical++ = dataHigh;

        *logical++ = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) |
                          ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x0E1B) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) |
                          ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)));

        *logical++ = dataLow;
    }

    if (Bytes)
        *Bytes = (Hardware->graphicsLargeVA) ? gcdRENDER_FENCE_LENGTH + 8 : gcdRENDER_FENCE_LENGTH;

    return gcvSTATUS_OK;
}

gceSTATUS
gckCONTEXT_HWSwitchCheckFence(gckCONTEXT Context, gctUINT32 ProcessID)
{
    gckHARDWARE hardware = gcvNULL;
    gckKERNEL kernel = gcvNULL;
    gckCOMMAND command = gcvNULL;
    gctUINT64 data = 0;
    gckVIDMEM_NODE node = gcvNULL;
    gctPOINTER logical = gcvNULL;
    gctSIZE_T bytes = 0;
    gctUINT32 timer = 0;
    gctUINT32 timeOut = 0;
    gctUINT64 stamp = 0;
    gceSTATUS status = gcvSTATUS_OK;

    hardware = Context->hardware;
    kernel = hardware->kernel;
    command = kernel->command;
    node = command->contextFence->videoMem;
    logical = command->contextFence->logical;
    gcmkVERIFY_OK(gckVIDMEM_NODE_GetSize(kernel, node, &bytes));
    stamp = Context->lastStamp;
    timeOut = kernel->timeOut / 10;

    do {
        gcmkVERIFY_OK(gckVIDMEM_NODE_InvalidateCache(kernel, node, 0, logical, bytes));
        /* Read fence memory */
        data = (gctUINT64)(*((gctUINT32_PTR)logical)) |
               ((gctUINT64)(*((gctUINT32_PTR)logical + 1)) << 32);
        if (data > stamp || data == stamp)
            break;
        gckOS_Udelay(hardware->os, 10);
    }
    while
        (++timer < timeOut);

    if (timer == timeOut || timer > timeOut)
        status = gcvSTATUS_TIMEOUT;

    return status;
}


#else
gceSTATUS
gckCONTEXT_Construct(gckOS Os, gckHARDWARE Hardware,
                     gctUINT32 ProcessID, gctBOOL Shared, gckCONTEXT *Context)
{
    gceSTATUS status;
    gckCONTEXT context = gcvNULL;
    gctUINT32 allocationSize;
    gctUINT i;
    gctPOINTER pointer = gcvNULL;
    gckCOMMAND command = gcvNULL;

    gcmkHEADER_ARG("Os=%p Hardware=%p", Os, Hardware);

    /* Verify the arguments. */
    gcmkVERIFY_OBJECT(Os, gcvOBJ_OS);
    gcmkVERIFY_ARGUMENT(Context != gcvNULL);

    /**************************************************************************/
    /* Allocate and initialize basic fields of gckCONTEXT. ********************/

    /* The context object size. */
    allocationSize = gcmSIZEOF(struct _gckCONTEXT);

    /* Allocate the object. */
    gcmkONERROR(gckOS_Allocate(Os, allocationSize, &pointer));

    context = pointer;

    /* Reset the entire object. */
    gcmkONERROR(gckOS_ZeroMemory(context, allocationSize));

    /* Initialize the gckCONTEXT object. */
    context->object.type = gcvOBJ_CONTEXT;
    context->os = Os;
    context->hardware = Hardware;

    context->entryPipe = gcvPIPE_3D;
    context->exitPipe = gcvPIPE_3D;

    /* Get the command buffer requirements. */
    gcmkONERROR(gckHARDWARE_QueryCommandBuffer(Hardware, gcvENGINE_RENDER,
                                               &context->alignment,
                                               &context->reservedHead, gcvNULL));

    /**************************************************************************/
    /* Get the size of the context buffer. ************************************/

    gcmkONERROR(_InitializeContextBuffer(context));

    if (context->maxState > 0) {
        command = context->hardware->kernel->command;

#if gcdSHARED_COMMAND_BUFFER
        if (Shared)
            command = context->hardware->kernel->sharedCommand;
# endif

        /**************************************************************************/
        /* Allocate and reset the state mapping table. ****************************/
        if (command->stateMap == gcvNULL) {
            /* Allocate the state mapping table. */
            gcmkONERROR(gckOS_Allocate(Os,
                                       gcmSIZEOF(gcsSTATE_MAP) * context->maxState,
                                       &pointer));

            context->map = pointer;

            /* Zero the state mapping table. */
            gcmkONERROR(gckOS_ZeroMemory(context->map, gcmSIZEOF(gcsSTATE_MAP) * context->maxState));

            command->stateMap = pointer;
        } else {
            context->map = command->stateMap;
        }
    }

    /**************************************************************************/
    /* Allocate the context and state delta buffers. **************************/

    for (i = 0; i < gcdCONTEXT_BUFFER_COUNT; i += 1) {
        /* Allocate a context buffer. */
        gcsCONTEXT_PTR buffer;

        /* Allocate the context buffer structure. */
        gcmkONERROR(gckOS_Allocate(Os, gcmSIZEOF(gcsCONTEXT), &pointer));

        buffer = pointer;

        /* Reset the context buffer structure. */
        gcmkVERIFY_OK(gckOS_ZeroMemory(buffer, gcmSIZEOF(gcsCONTEXT)));

        /* Append to the list. */
        if (context->buffer == gcvNULL) {
            buffer->next = buffer;
            context->buffer = buffer;
        } else {
            buffer->next = context->buffer->next;
            context->buffer->next = buffer;
        }

        /* Set the number of delta in the order of creation. */
#if gcmIS_DEBUG(gcdDEBUG_CODE)
        buffer->num = i;
# endif

        /* Create the busy signal. */
        gcmkONERROR(gckOS_CreateSignal(Os, gcvFALSE, &buffer->signal));

        /* Set the signal, buffer is currently not busy. */
        gcmkONERROR(gckOS_Signal(Os, buffer->signal, gcvTRUE));

        /* Create a new physical context buffer. */
        gcmkONERROR(_AllocateContextBuffer(context, buffer));

        /* Set gckEVENT object pointer. */
        buffer->eventObj = Hardware->kernel->eventObj;

        /* Set the pointers to the LINK commands. */
        if (context->linkIndex2D != 0)
            buffer->link2D = &buffer->logical[context->linkIndex2D];

        if (context->linkIndex3D != 0)
            buffer->link3D = &buffer->logical[context->linkIndex3D];

        if (context->linkIndexXD != 0) {
            gctPOINTER xdLink;
            gctADDRESS xdEntryAddress;
            gctUINT32 xdEntrySize;
            gctUINT32 linkBytes;

            /* Determine LINK parameters. */
            xdLink = &buffer->logical[context->linkIndexXD];

            xdEntryAddress = buffer->address + context->entryOffsetXDFrom3D;

            xdEntrySize = context->bufferSize - context->entryOffsetXDFrom3D;

            /* Query LINK size. */
            gcmkONERROR(gckWLFE_Link(Hardware, gcvNULL, 0, 0,
                                     &linkBytes, gcvNULL, gcvNULL));

            /* Generate a LINK. */
            gcmkONERROR(gckWLFE_Link(Hardware, xdLink, xdEntryAddress,
                                     xdEntrySize, &linkBytes, gcvNULL, gcvNULL));
        }
    }

    /**************************************************************************/
    /* Initialize the context buffers. ****************************************/

    /* Initialize the current context buffer. */
    gcmkONERROR(_InitializeContextBuffer(context));

#if gcdENABLE_SW_PREEMPTION
    if (context->maxState > 0 && context->numStates > 0) {
        for (i = 0; i < gcdCONTEXT_BUFFER_COUNT + 1; i += 1) {
            /* Allocate a state delta. */
            gcsSTATE_DELTA_PTR delta = gcvNULL;
            gcsSTATE_DELTA_PTR prev;

            /* Allocate the state delta structure. */
            _AllocateDelta(context, &delta);

            /* Append to the list. */
            if (context->delta == gcvNULL) {
                delta->prev = gcmPTR_TO_UINT64(delta);
                delta->next = gcmPTR_TO_UINT64(delta);
                context->deltaHead = delta;
                context->delta = delta;
            } else {
                delta->next = gcmPTR_TO_UINT64(context->delta);
                delta->prev = context->delta->prev;

                prev = gcmUINT64_TO_PTR(context->delta->prev);
                prev->next = gcmPTR_TO_UINT64(delta);
                context->delta->prev = gcmPTR_TO_UINT64(delta);
            }
        }
    }

    if (gckHARDWARE_IsFeatureAvailable(context->hardware, gcvFEATURE_HALTI5) &&
        !(gckHARDWARE_IsFeatureAvailable(context->hardware, gcvFEATURE_SMALL_BATCH) &&
        context->hardware->options.smallBatch)) {
        mirroredStatesCount = ARRAY_SIZE(mirroredStates);
    }

    context->prevRecordArray = gcvNULL;
    context->prevMapEntryID = gcvNULL;
    context->prevMapEntryIndex = gcvNULL;
    context->prevDeltaPtr = gcvNULL;
# endif

    /* Make all created contexts equal. */
    {
        gcsCONTEXT_PTR currContext, tempContext;

        /* Set the current context buffer. */
        currContext = context->buffer;

        /* Get the next context buffer. */
        tempContext = currContext->next;

        /* Loop through all buffers. */
        while (tempContext != currContext) {
            if (tempContext == gcvNULL)
                gcmkONERROR(gcvSTATUS_NOT_FOUND);

            /* Copy the current context. */
            gckOS_MemCopy(tempContext->logical, currContext->logical, context->totalSize);

            /* Get the next context buffer. */
            tempContext = tempContext->next;
        }
    }

    /* Return pointer to the gckCONTEXT object. */
    *Context = context;

    /* Success. */
    gcmkFOOTER_ARG("*Context=%p", *Context);
    return gcvSTATUS_OK;

OnError:
    /* Roll back on error. */
    gcmkVERIFY_OK(_DestroyContext(context));

    /* Return the status. */
    gcmkFOOTER();
    return status;
}

gceSTATUS
gckCONTEXT_Destroy(gckCONTEXT Context)
{
    gceSTATUS status;

    gcmkHEADER_ARG("Context=%p", Context);

    /* Verify the arguments. */
    gcmkVERIFY_OBJECT(Context, gcvOBJ_CONTEXT);

    /* Destroy the context and all related objects. */
    status = _DestroyContext(Context);

    /* Success. */
    gcmkFOOTER_NO();
    return status;
}

/******************************************************************************\
 **
 **  gckCONTEXT_Update
 **
 **  Merge all pending state delta buffers into the current context buffer.
 **
 **  INPUT:
 **
 **      gckCONTEXT Context
 **          Pointer to an gckCONTEXT object.
 **
 **      gctUINT32 ProcessID
 **          Current process ID.
 **
 **      gcsSTATE_DELTA_PTR StateDelta
 **          Pointer to the state delta.
 **
 **  OUTPUT:
 **
 **      Nothing.
 */

gceSTATUS
gckCONTEXT_Update(gckCONTEXT Context, gctUINT32 ProcessID, gcsSTATE_DELTA_PTR StateDelta)
{
    gceSTATUS status = gcvSTATUS_OK;
    gcsSTATE_DELTA _stateDelta;
    gckKERNEL kernel;
    gcsCONTEXT_PTR buffer;
    gcsSTATE_MAP_PTR map;
    gctBOOL needCopy = gcvFALSE;
    gcsSTATE_DELTA_PTR nDelta;
    gcsSTATE_DELTA_PTR uDelta = gcvNULL;
    gcsSTATE_DELTA_PTR kDelta = gcvNULL;
    gcsSTATE_DELTA_RECORD_PTR record;
    gcsSTATE_DELTA_RECORD_PTR recordArray = gcvNULL;
    gctUINT elementCount;
    gctUINT address;
    gctUINT32 mask;
    gctUINT32 data;
    gctUINT index;
    gctUINT i, j;
    gctUINT32 dirtyRecordArraySize = 0;

    gcmkHEADER_ARG("Context=%p ProcessID=%d StateDelta=%p",
                   Context, ProcessID, StateDelta);

    /* Verify the arguments. */
    gcmkVERIFY_OBJECT(Context, gcvOBJ_CONTEXT);

    /* Get a shortcut to the kernel object. */
    kernel = Context->hardware->kernel;

    /* Check wehther we need to copy the structures or not. */
    gcmkONERROR(gckOS_QueryNeedCopy(Context->os, ProcessID, &needCopy));

    /* Get the current context buffer. */
    buffer = Context->buffer;

    /*
     * Wait until the context buffer becomes available; this will
     * also reset the signal and mark the buffer as busy.
     */
    gcmkONERROR(gckOS_WaitSignal(Context->os, buffer->signal, gcvFALSE, kernel->timeOut));

#if gcmIS_DEBUG(gcdDEBUG_CODE) && 1
    /* Update current context token. */
    buffer->logical[Context->map[0x0E14].index] = (gctUINT32)gcmPTR2INT32(Context);
# endif

    /* Are there any pending deltas? */
    if (buffer->deltaCount != 0) {
        /* Get the state map. */
        map = Context->map;

        /* Get the first delta item. */
        uDelta = buffer->delta;

        /* Reset the vertex stream count. */
        elementCount = 0;

        /* Merge all pending deltas. */
        for (i = 0; i < buffer->deltaCount; i += 1) {
            /* Get access to the state delta. */
            gcmkONERROR(gckKERNEL_OpenUserData(kernel, needCopy,
                                               &_stateDelta, uDelta,
                                               gcmSIZEOF(gcsSTATE_DELTA),
                                               (gctPOINTER *)&kDelta));

            dirtyRecordArraySize = gcmSIZEOF(gcsSTATE_DELTA_RECORD) * kDelta->recordCount;

            if (dirtyRecordArraySize) {
                /* Get access to the state records. */
                gcmkONERROR(gckOS_MapUserPointer(kernel->os,
                                                 gcmUINT64_TO_PTR(kDelta->recordArray),
                                                 dirtyRecordArraySize,
                                                 (gctPOINTER *)&recordArray));

                if (recordArray == gcvNULL)
                    gcmkONERROR(gcvSTATUS_INVALID_ARGUMENT);

                /* Merge all pending states. */
                for (j = 0; j < kDelta->recordCount; j += 1) {
                    if (j >= Context->numStates)
                        break;

                    /* Get the current state record. */
                    record = &recordArray[j];

                    /* Get the state address. */
                    gcmkONERROR(gckOS_ReadMappedPointer(kernel->os, &record->address, &address));

                    /* Make sure the state is a part of the mapping table. */
                    if (address >= Context->maxState) {
                        gcmkTRACE(gcvLEVEL_ERROR,
                                  "%s(%d): State 0x%04X (0x%04X) is not mapped.\n",
                                  __FUNCTION__, __LINE__, address, address << 2);

                        continue;
                    }

                    /* Get the state index. */
                    index = map[address].index;

                    /* Skip the state if not mapped. */
                    if (index == 0) {
                        continue;
                    }

                    /* Get the data mask. */
                    gcmkONERROR(gckOS_ReadMappedPointer(kernel->os, &record->mask, &mask));

                    /* Get the new data value. */
                    gcmkONERROR(gckOS_ReadMappedPointer(kernel->os, &record->data, &data));

                    /* Masked states that are being completely reset or regular states. */
                    if (mask == 0 || (mask == ~0U)) {
                        /* Process special states. */
                        if (address == 0x0595) {
                            /* Force auto-disable to be disabled. */
                            data = ((((gctUINT32) (data)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5)));
                            data = ((((gctUINT32) (data)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:4) - (0 ? 4:4) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:4) - (0 ? 4:4) + 1))))))) << (0 ? 4:4))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 4:4) - (0 ? 4:4) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:4) - (0 ? 4:4) + 1))))))) << (0 ? 4:4)));
                            data = ((((gctUINT32) (data)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 13:13) - (0 ? 13:13) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 13:13) - (0 ? 13:13) + 1))))))) << (0 ? 13:13))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 13:13) - (0 ? 13:13) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 13:13) - (0 ? 13:13) + 1))))))) << (0 ? 13:13)));
                        }

                        /* Set new data. */
                        buffer->logical[index] = data;
                    } else {
                        /* Masked states that are being set partially. */
                        buffer->logical[index] = (~mask & buffer->logical[index]) | (mask & data);
                    }
                }
            }

            /* Get the element count. */
            if (kDelta->elementCount != 0)
                elementCount = kDelta->elementCount;

            /* Dereference delta. */
            kDelta->refCount -= 1;

            gcmkASSERT(kDelta->refCount >= 0);

            /* Get the next state delta. */
            nDelta = gcmUINT64_TO_PTR(kDelta->next);

            if (dirtyRecordArraySize) {
                /* Get access to the state records. */
                gcmkONERROR(gckOS_UnmapUserPointer(kernel->os,
                                                   gcmUINT64_TO_PTR(kDelta->recordArray),
                                                   dirtyRecordArraySize, recordArray));

                recordArray = gcvNULL;
            }

            /* Close access to the current state delta. */
            gcmkONERROR(gckKERNEL_CloseUserData(kernel, needCopy, gcvTRUE, uDelta,
                                                gcmSIZEOF(gcsSTATE_DELTA), (gctPOINTER *)&kDelta));

            /* Update the user delta pointer. */
            uDelta = nDelta;
        }

        /*
         * Hardware disables all input attribute when the attribute 0 is programmed,
         * it then reenables those attributes that were explicitly programmed by
         * the software. Because of this we cannot program the entire array of
         * values, otherwise we'll get all attributes reenabled, but rather program
         * only those that are actully needed by the software.
         * elementCount = attribCount + 1 to make sure 0 is a flag to indicate if UMD
         * touches it.
         */
        if (elementCount != 0) {
            gctUINT base;
            gctUINT nopCount;
            gctUINT32_PTR nop;
            gctUINT fe2vsCount;
            gctUINT attribCount = elementCount - 1;
            gctUINT32 feAttributeStatgeAddr = 0x0180;

            if (gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_HALTI5)) {
                fe2vsCount = 32;
                base = map[0x5E00].index;
                feAttributeStatgeAddr = 0x5E00;
            } else if (gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_HALTI0)) {
                fe2vsCount = 16;
                base = map[0x0180].index;
            } else {
                fe2vsCount = 12;
                base = map[0x0180].index;
            }

            /* Set the proper state count. */
            if (attribCount == 0) {
                gcmkASSERT(gckHARDWARE_IsFeatureAvailable(Context->hardware,
                                                          gcvFEATURE_ZERO_ATTRIB_SUPPORT));

                buffer->logical[base - 1] =
                    ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)))
                  | ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26)))
                  |      ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)))
                  |      ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (feAttributeStatgeAddr) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                /* Set the proper state count. */
                buffer->logical[base + 1] =
                    ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)))
                  | ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26)))
                  |      ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)))
                  |      ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x01F2) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));
                buffer->logical[base + 2] = 0x1;
                attribCount               = 3;
            } else {
                buffer->logical[base - 1] =
                    ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)))
                  | ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26)))
                  |      ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (attribCount) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)))
                  |      ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (feAttributeStatgeAddr) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));
            }

            /* Determine the number of NOP commands. */
            nopCount = (fe2vsCount / 2) - (attribCount / 2);
            /* Determine the location of the first NOP. */
            nop = &buffer->logical[base + (attribCount | 1)];

            /* Fill the unused space with NOPs. */
            for (i = 0; i < nopCount; i += 1) {
                if (nop >= buffer->logical + Context->totalSize)
                    break;

                /* Generate a NOP command. */
                *nop = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x03 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));

                /* Advance. */
                nop += 2;
            }
        }

        if (gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_SMALL_BATCH) &&
            Context->hardware->options.smallBatch) {
            gctUINT numConstant = (gctUINT)Context->hardware->identity.numConstants;
            gctUINT32 constCount = 0;

            /* Get the const number after merge. */
            index = map[0x042B].index;
            data = buffer->logical[index];
            constCount = (((((gctUINT32) (data)) >> (0 ? 8:0)) & ((gctUINT32) ((((1 ? 8:0) - (0 ? 8:0) + 1) == 32) ? ~0U : (~(~0U << ((1 ? 8:0) - (0 ? 8:0) + 1)))))) );

            _UpdateUnifiedReg(Context,
                              0xD000,
                              numConstant << 2, constCount << 2);
        }

        if (gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_SMALL_BATCH) &&
            Context->hardware->options.smallBatch &&
            (!gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_SH_SUPPORT_SEPARATED_TEX))) {
            gctUINT numSamplers = 80;
            gctUINT32 samplerCount = 0;

            /* Get the sampler number after merge. */
            index = map[0x042C].index;
            data = buffer->logical[index];
            samplerCount = (((((gctUINT32) (data)) >> (0 ? 6:0)) & ((gctUINT32) ((((1 ? 6:0) - (0 ? 6:0) + 1) == 32) ? ~0U : (~(~0U << ((1 ? 6:0) - (0 ? 6:0) + 1)))))) );

            _UpdateUnifiedReg(Context, 0x5800, numSamplers, samplerCount);
            _UpdateUnifiedReg(Context, 0x5880, numSamplers, samplerCount);
            _UpdateUnifiedReg(Context, 0x5900, numSamplers, samplerCount);
            _UpdateUnifiedReg(Context, 0x5980, numSamplers, samplerCount);
            _UpdateUnifiedReg(Context, 0x5A00, numSamplers, samplerCount);
            _UpdateUnifiedReg(Context, 0x5600, numSamplers, samplerCount);
            _UpdateUnifiedReg(Context, 0x5680, numSamplers, samplerCount);
        }
        /* Reset pending deltas. */
        buffer->deltaCount = 0;
        buffer->delta = gcvNULL;
    }

    if (StateDelta) {
        /* Set state delta user pointer. */
        uDelta = StateDelta;

        /* Get access to the state delta. */
        gcmkONERROR(gckKERNEL_OpenUserData(kernel, needCopy, &_stateDelta, uDelta,
                                           gcmSIZEOF(gcsSTATE_DELTA), (gctPOINTER *)&kDelta));

        /* State delta cannot be attached to anything yet. */
        if (kDelta->refCount != 0) {
            gcmkTRACE(gcvLEVEL_ERROR,
                      "%s(%d): kDelta->refCount = %d (has to be 0).\n",
                      __FUNCTION__, __LINE__, kDelta->refCount);
        }

        /* Attach to all contexts. */
        buffer = Context->buffer;

        do {
            /*
             * Attach to the context if nothing is attached yet. If a delta
             * is allready attached, all we need to do is to increment
             * the number of deltas in the context.
             */
            if (buffer->delta == gcvNULL)
                buffer->delta = uDelta;

            /* Update reference count. */
            kDelta->refCount += 1;

            /* Update counters. */
            buffer->deltaCount += 1;

            /* Get the next context buffer. */
            buffer = buffer->next;

            if (buffer == gcvNULL)
                gcmkONERROR(gcvSTATUS_NOT_FOUND);
        } while (Context->buffer != buffer);

        /* Close access to the current state delta. */
        gcmkONERROR(gckKERNEL_CloseUserData(kernel, needCopy, gcvTRUE, uDelta,
                                            gcmSIZEOF(gcsSTATE_DELTA), (gctPOINTER *)&kDelta));
    }
    /* Schedule an event to mark the context buffer as available. */
    gcmkONERROR(gckEVENT_Signal(buffer->eventObj, buffer->signal, gcvKERNEL_PIXEL));

    /* Advance to the next context buffer. */
    Context->buffer = buffer->next;

    /* Return the status. */
    gcmkFOOTER();
    return gcvSTATUS_OK;

OnError:
    /* Get access to the state records. */
    if (kDelta != gcvNULL && recordArray != gcvNULL) {
        gcmkVERIFY_OK(gckOS_UnmapUserPointer(kernel->os,
                                             gcmUINT64_TO_PTR(kDelta->recordArray),
                                             dirtyRecordArraySize, (gctPOINTER *)&recordArray));
    }

    /* Close access to the current state delta. */
    gcmkVERIFY_OK(gckKERNEL_CloseUserData(kernel, needCopy, gcvTRUE, uDelta,
                                          gcmSIZEOF(gcsSTATE_DELTA), (gctPOINTER *)&kDelta));

    /* Return the status. */
    gcmkFOOTER();

    return status;
}

gceSTATUS
gckCONTEXT_MapBuffer(gckCONTEXT Context, gctUINT64 *Logicals, gctUINT32 *Bytes)
{
    gceSTATUS status;
    int i = 0;
    gckKERNEL kernel = Context->hardware->kernel;
    gctPOINTER logical;
    gcsCONTEXT_PTR buffer;

    gcmkHEADER_ARG("Context=%p", Context);

    buffer = Context->buffer;

    for (i = 0; i < gcdCONTEXT_BUFFER_COUNT; i++) {
        /* Lock for userspace CPU access. */
        gcmkONERROR(gckVIDMEM_NODE_LockCPU(kernel, buffer->videoMem,
                                           gcvFALSE, gcvTRUE, &logical));

        Logicals[i] = gcmPTR_TO_UINT64(logical);
        buffer = buffer->next;
    }

    *Bytes = (gctUINT)Context->totalSize;

    gcmkFOOTER_NO();
    return gcvSTATUS_OK;

OnError:
    gcmkFOOTER();
    return status;
}

#endif /* gcdHARDWARE_CONTEXT_SWITCH */

#if gcdENABLE_SW_PREEMPTION
static void
_CopyDelta(gcsSTATE_DELTA_PTR DstDelta, gcsSTATE_DELTA_PTR SrcDelta)
{
    DstDelta->recordCount = SrcDelta->recordCount;

    if (DstDelta->recordCount) {
        gckOS_MemCopy(gcmUINT64_TO_PTR(DstDelta->recordArray),
                      gcmUINT64_TO_PTR(SrcDelta->recordArray),
                      gcmSIZEOF(gcsSTATE_DELTA_RECORD) * DstDelta->recordCount);
    }

    if (SrcDelta->mapEntryIDSize) {
        gckOS_MemCopy(gcmUINT64_TO_PTR(DstDelta->mapEntryID),
                      gcmUINT64_TO_PTR(SrcDelta->mapEntryID),
                      SrcDelta->mapEntryIDSize);

        gckOS_MemCopy(gcmUINT64_TO_PTR(DstDelta->mapEntryIndex),
                      gcmUINT64_TO_PTR(SrcDelta->mapEntryIndex),
                      SrcDelta->mapEntryIDSize);
    }

    DstDelta->mapEntryIDSize = SrcDelta->mapEntryIDSize;
    DstDelta->id = SrcDelta->id;
    DstDelta->elementCount = SrcDelta->elementCount;
}

static void
_MergeDelta(gcsSTATE_DELTA_PTR StateDelta, gctUINT32 Address,
            gctUINT32 Mask, gctUINT32 Data)
{
    gcsSTATE_DELTA_RECORD_PTR recordArray;
    gcsSTATE_DELTA_RECORD_PTR recordEntry;
    gctUINT32_PTR mapEntryID;
    gctUINT32_PTR mapEntryIndex;
    gctUINT deltaID;
    gctUINT32 i;

    if (!StateDelta)
        return;

    /* Get the current record array. */
    recordArray = (gcsSTATE_DELTA_RECORD_PTR)(gcmUINT64_TO_PTR(StateDelta->recordArray));

    /* Get shortcuts to the fields. */
    deltaID = StateDelta->id;
    mapEntryID = (gctUINT32_PTR)(gcmUINT64_TO_PTR(StateDelta->mapEntryID));
    mapEntryIndex = (gctUINT32_PTR)(gcmUINT64_TO_PTR(StateDelta->mapEntryIndex));

    gcmkASSERT(Address < (StateDelta->mapEntryIDSize / gcmSIZEOF(gctUINT)));

    for (i = 0; i < mirroredStatesCount; i++) {
        if (Address >= mirroredStates[i].inputBase &&
            (Address < (mirroredStates[i].inputBase + mirroredStates[i].count))) {
            Address = mirroredStates[i].outputBase + (Address - mirroredStates[i].inputBase);
            break;
        }
    }

    /* Has the entry been initialized? */
    if (mapEntryID[Address] != deltaID) {
        /* No, initialize the map entry. */
        mapEntryID[Address] = deltaID;
        mapEntryIndex[Address] = StateDelta->recordCount;

        /* Get the current record. */
        recordEntry = &recordArray[mapEntryIndex[Address]];

        /* Add the state to the list. */
        recordEntry->address = Address;
        recordEntry->mask = Mask;
        recordEntry->data = Data;

        /* Update the number of valid records. */
        StateDelta->recordCount += 1;
    }

    /* Regular (not masked) states. */
    else if (Mask == 0) {
        /* Get the current record. */
        recordEntry = &recordArray[mapEntryIndex[Address]];

        /* Update the state record. */
        recordEntry->mask = 0;
        recordEntry->data = Data;
    } else { /* Masked states. */
        /* Get the current record. */
        recordEntry = &recordArray[mapEntryIndex[Address]];

        /* Update the state record. */
        recordEntry->mask |= Mask;
        recordEntry->data &= ~Mask;
        recordEntry->data |= (Data & Mask);
    }
}

/******************************************************************************\
 **
 **  gckCONTEXT_UpdateDelta
 **
 **  Update delta in kernel driver.
 **
 **  INPUT:
 **
 **      gckCONTEXT Context
 **          Pointer to an gckCONTEXT object.
 **
 **      gcsSTATE_DELTA_PTR Delta
 **          Pointer to the state delta.
 */
gceSTATUS
gckCONTEXT_UpdateDelta(gckCONTEXT Context, gcsSTATE_DELTA_PTR Delta)
{
    gceSTATUS status = gcvSTATUS_OK;
    gcsSTATE_DELTA_PTR delta = gcvNULL;
    gcsSTATE_DELTA_PTR prevDelta = gcvNULL;
    gcsCONTEXT_PTR buffer = gcvNULL;
    gcsSTATE_DELTA_RECORD_PTR record = gcvNULL;

    gcmkHEADER_ARG("Context=%p Delta=%p", Context, Delta);

    /* Verify the arguments. */
    gcmkVERIFY_OBJECT(Context, gcvOBJ_CONTEXT);
    gcmkVERIFY_ARGUMENT(Delta != gcvNULL);

    delta = Delta;

    if (delta && Context->delta) {
        _CopyDelta(Context->delta, delta);

        buffer = Context->buffer;

        do {
            if (buffer->kDelta == gcvNULL)
                buffer->kDelta = Context->delta;

            buffer->kDeltaCount = 1;

            buffer = buffer->next;

            if (buffer == gcvNULL)
                gcmkONERROR(gcvSTATUS_NOT_FOUND);
        } while (Context->buffer != buffer);

        if (Context->deltaHead != Context->delta) {
            gctUINT count = 0;
            gctUINT i = 0;

            delta = Context->delta;

            count = delta->recordCount;

            record = gcmUINT64_TO_PTR(delta->recordArray);

            prevDelta = gcmUINT64_TO_PTR(delta->prev);

            /* Go through all records. */
            for (i = 0; i < count; i += 1) {
                _MergeDelta(prevDelta, record->address, record->mask, record->data);

                /* Advance to the next state. */
                record += 1;
            }

            /* Update the element count. */
            if (delta->elementCount != 0)
                prevDelta->elementCount = delta->elementCount;
        } else {
            Context->delta = (gcsSTATE_DELTA_PTR)gcmUINT64_TO_PTR(Context->delta->next);
        }

        _ResetDelta(Context->delta);
    }

OnError:
    gcmkFOOTER();
    return status;
}

/******************************************************************************\
 **
 **  gckCONTEXT_PreemptUpdate
 **
 **  Context update in preemption mode.
 **
 **  INPUT:
 **
 **      gckCONTEXT Context
 **          Pointer to an gckCONTEXT object.
 **
 **      gckPREEMPT_COMMIT PreemptCommit
 **          The preemptCommit.
 */
gceSTATUS
gckCONTEXT_PreemptUpdate(gckCONTEXT Context, gckPREEMPT_COMMIT PreemptCommit)
{
    gceSTATUS status = gcvSTATUS_OK;
    gcsCONTEXT_PTR buffer;
    gckKERNEL kernel;
    gcsSTATE_MAP_PTR map;
    gcsSTATE_DELTA_RECORD_PTR record;
    gcsSTATE_DELTA_RECORD_PTR recordArray = gcvNULL;
    gctUINT elementCount;
    gctUINT address;
    gctUINT32 mask;
    gctUINT32 data;
    gctUINT index;
    gctUINT i, j;
    gctUINT32 dirtyRecordArraySize = 0;
    gcsSTATE_DELTA_PTR kDelta = gcvNULL;

    gcmkHEADER_ARG("Context=%p PreemptCommit=%p", Context, PreemptCommit);

    /* Verify the arguments. */
    gcmkVERIFY_OBJECT(Context, gcvOBJ_CONTEXT);

    buffer = Context->buffer;
    kernel = Context->hardware->kernel;

    gcmkONERROR(gckOS_WaitSignal(Context->os, buffer->signal, gcvFALSE, kernel->timeOut));

    /* Are there any pending deltas? */
    if (buffer->kDeltaCount != 0) {
        /* Get the state map. */
        map = Context->map;

        kDelta = buffer->kDelta;

        /* Reset the vertex stream count. */
        elementCount = 0;

        /* Merge all pending deltas. */
        for (i = 0; i < buffer->kDeltaCount; i += 1) {
            dirtyRecordArraySize = gcmSIZEOF(gcsSTATE_DELTA_RECORD) * kDelta->recordCount;

            if (dirtyRecordArraySize) {
                /* Merge all pending states. */
                for (j = 0; j < kDelta->recordCount; j += 1) {
                    if (j >= Context->numStates)
                        break;

                    recordArray = gcmUINT64_TO_PTR(kDelta->recordArray);

                    /* Get the current state record. */
                    record = &recordArray[j];

                    /* Get the state address. */
                    address = record->address;

                    /* Make sure the state is a part of the mapping table. */
                    if (address >= Context->maxState) {
                        gcmkTRACE(gcvLEVEL_ERROR,
                                  "%s(%d): State 0x%04X (0x%04X) is not mapped.\n",
                                  __FUNCTION__, __LINE__, address, address << 2);

                        continue;
                    }

                    /* Get the state index. */
                    index = map[address].index;

                    /* Skip the state if not mapped. */
                    if (index == 0) {
                        continue;
                    }

                    /* Get the data mask. */
                    mask = record->mask;

                    /* Get the new data value. */
                    data = record->data;

                    /* Masked states that are being completely reset or regular states. */
                    if (mask == 0 || (mask == ~0U)) {
                        /* Process special states. */
                        if (address == 0x0595) {
                            /* Force auto-disable to be disabled. */
                            data = ((((gctUINT32) (data)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 5:5) - (0 ? 5:5) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 5:5) - (0 ? 5:5) + 1))))))) << (0 ? 5:5)));
                            data = ((((gctUINT32) (data)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 4:4) - (0 ? 4:4) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:4) - (0 ? 4:4) + 1))))))) << (0 ? 4:4))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 4:4) - (0 ? 4:4) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 4:4) - (0 ? 4:4) + 1))))))) << (0 ? 4:4)));
                            data = ((((gctUINT32) (data)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 13:13) - (0 ? 13:13) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 13:13) - (0 ? 13:13) + 1))))))) << (0 ? 13:13))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 13:13) - (0 ? 13:13) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 13:13) - (0 ? 13:13) + 1))))))) << (0 ? 13:13)));
                        }

                        /* Set new data. */
                        buffer->logical[index] = data;
                    } else { /* Masked states that are being set partially. */
                        buffer->logical[index] =
                            (~mask & buffer->logical[index]) | (mask & data);
                    }
                }
            }

            /* Get the element count. */
            if (kDelta->elementCount != 0)
                elementCount = kDelta->elementCount;

            if (dirtyRecordArraySize)
                recordArray = gcvNULL;

            /* Get the next state delta. */
            kDelta = gcmUINT64_TO_PTR(kDelta->next);
        }

        /*
         * Hardware disables all input attribute when the attribute 0 is programmed,
         * it then reenables those attributes that were explicitly programmed by
         * the software. Because of this we cannot program the entire array of
         * values, otherwise we'll get all attributes reenabled, but rather program
         * only those that are actully needed by the software.
         * elementCount = attribCount + 1 to make sure 0 is a flag to indicate if UMD
         * touches it.
         */
        if (elementCount != 0) {
            gctUINT base;
            gctUINT nopCount;
            gctUINT32_PTR nop;
            gctUINT fe2vsCount;
            gctUINT attribCount = elementCount - 1;
            gctUINT32 feAttributeStatgeAddr = 0x0180;

            if (gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_HALTI5)) {
                fe2vsCount = 32;
                base = map[0x5E00].index;
                feAttributeStatgeAddr = 0x5E00;
            } else if (gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_HALTI0)) {
                fe2vsCount = 16;
                base = map[0x0180].index;
            } else {
                fe2vsCount = 12;
                base = map[0x0180].index;
            }

            /* Set the proper state count. */
            if (attribCount == 0) {
                gcmkASSERT(gckHARDWARE_IsFeatureAvailable(Context->hardware,
                                                          gcvFEATURE_ZERO_ATTRIB_SUPPORT));

                buffer->logical[base - 1] =
                    ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)))
                  | ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26)))
                  |      ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)))
                  |      ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (feAttributeStatgeAddr) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));

                /* Set the proper state count. */
                buffer->logical[base + 1] =
                    ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)))
                  | ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26)))
                  |      ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (1) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)))
                  |      ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (0x01F2) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));
                buffer->logical[base + 2] = 0x1;
                attribCount               = 3;
            } else {
                buffer->logical[base - 1] =
                    ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x01 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)))
                  | ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26))) | (((gctUINT32) (0x0 & ((gctUINT32) ((((1 ? 26:26) - (0 ? 26:26) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 26:26) - (0 ? 26:26) + 1))))))) << (0 ? 26:26)))
                  |      ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16))) | (((gctUINT32) ((gctUINT32) (attribCount) & ((gctUINT32) ((((1 ? 25:16) - (0 ? 25:16) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 25:16) - (0 ? 25:16) + 1))))))) << (0 ? 25:16)))
                  |      ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0))) | (((gctUINT32) ((gctUINT32) (feAttributeStatgeAddr) & ((gctUINT32) ((((1 ? 15:0) - (0 ? 15:0) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 15:0) - (0 ? 15:0) + 1))))))) << (0 ? 15:0)));
            }

            /* Determine the number of NOP commands. */
            nopCount = (fe2vsCount / 2) - (attribCount / 2);
            /* Determine the location of the first NOP. */
            nop = &buffer->logical[base + (attribCount | 1)];

            /* Fill the unused space with NOPs. */
            for (i = 0; i < nopCount; i += 1) {
                if (nop >= buffer->logical + Context->totalSize)
                    break;

                /* Generate a NOP command. */
                *nop = ((((gctUINT32) (0)) & ~(((gctUINT32) (((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27))) | (((gctUINT32) (0x03 & ((gctUINT32) ((((1 ? 31:27) - (0 ? 31:27) + 1) ==
 32) ? ~0U : (~(~0U << ((1 ? 31:27) - (0 ? 31:27) + 1))))))) << (0 ? 31:27)));

                /* Advance. */
                nop += 2;
            }
        }

        if (gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_SMALL_BATCH) &&
            Context->hardware->options.smallBatch) {
            gctUINT numConstant = (gctUINT)Context->hardware->identity.numConstants;
            gctUINT32 constCount = 0;

            /* Get the const number after merge. */
            index = map[0x042B].index;
            data = buffer->logical[index];
            constCount = (((((gctUINT32) (data)) >> (0 ? 8:0)) & ((gctUINT32) ((((1 ? 8:0) - (0 ? 8:0) + 1) == 32) ? ~0U : (~(~0U << ((1 ? 8:0) - (0 ? 8:0) + 1)))))) );

            _UpdateUnifiedReg(Context, 0xD000, numConstant << 2, constCount << 2);
        }

        if (gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_SMALL_BATCH) &&
            Context->hardware->options.smallBatch &&
            (!gckHARDWARE_IsFeatureAvailable(Context->hardware, gcvFEATURE_SH_SUPPORT_SEPARATED_TEX))) {
            gctUINT numSamplers = 80;
            gctUINT32 samplerCount = 0;

            /* Get the sampler number after merge. */
            index = map[0x042C].index;
            data = buffer->logical[index];
            samplerCount = (((((gctUINT32) (data)) >> (0 ? 6:0)) & ((gctUINT32) ((((1 ? 6:0) - (0 ? 6:0) + 1) == 32) ? ~0U : (~(~0U << ((1 ? 6:0) - (0 ? 6:0) + 1)))))) );

            _UpdateUnifiedReg(Context, 0x5800, numSamplers, samplerCount);
            _UpdateUnifiedReg(Context, 0x5880, numSamplers, samplerCount);
            _UpdateUnifiedReg(Context, 0x5900, numSamplers, samplerCount);
            _UpdateUnifiedReg(Context, 0x5980, numSamplers, samplerCount);
            _UpdateUnifiedReg(Context, 0x5A00, numSamplers, samplerCount);
            _UpdateUnifiedReg(Context, 0x5600, numSamplers, samplerCount);
            _UpdateUnifiedReg(Context, 0x5680, numSamplers, samplerCount);
        }

        /* Reset pending deltas. */
        buffer->kDeltaCount = 0;
    }

    /* Schedule an event to mark the context buffer as available. */
    gcmkONERROR(gckEVENT_Signal(buffer->eventObj, buffer->signal, gcvKERNEL_PIXEL));

    /* Advance to the next context buffer. */
    Context->buffer = buffer->next;

OnError:
    gcmkFOOTER();
    return status;
}

/* Destroy previous context switch delta. */
gceSTATUS
gckCONTEXT_DestroyPrevDelta(gckCONTEXT Context)
{
    gceSTATUS status = gcvSTATUS_OK;

    gcmkHEADER_ARG("Context=%p", Context);

    if (Context->prevRecordArray)
        gcmkVERIFY_OK(gcmkOS_SAFE_FREE(Context->os, Context->prevRecordArray));

    if (Context->prevMapEntryID)
        gcmkVERIFY_OK(gcmkOS_SAFE_FREE(Context->os, Context->prevMapEntryID));

    if (Context->prevMapEntryIndex)
        gcmkVERIFY_OK(gcmkOS_SAFE_FREE(Context->os, Context->prevMapEntryIndex));

    Context->prevDeltaPtr = gcvNULL;

    gcmkFOOTER();

    return status;
}

/* Construct and store previous context switch delta. */
gceSTATUS
gckCONTEXT_ConstructPrevDelta(gckCONTEXT Context, gctUINT32 ProcessID, gcsSTATE_DELTA_PTR StateDelta)
{
    gceSTATUS status = gcvSTATUS_OK;
    gcsSTATE_DELTA_PTR uDelta = gcvNULL;
    gcsSTATE_DELTA_PTR kDelta = gcvNULL;
    gcsSTATE_DELTA_RECORD_PTR kRecordArray = gcvNULL;
    gctBOOL needCopy = gcvFALSE;
    gctPOINTER pointer = gcvNULL;
    gctUINT32 dirtyRecordArraySize = 0;
    gckKERNEL kernel = gcvNULL;
    gctBOOL allocated = gcvFALSE;

    gcmkHEADER_ARG("Context=%p ProcessID=%d StateDelta=%p",
                   Context, ProcessID, StateDelta);

    /* Verify the arguments. */
    gcmkVERIFY_OBJECT(Context, gcvOBJ_CONTEXT);

    if (StateDelta) {
        kernel = Context->hardware->kernel;

        gcmkVERIFY_OK(gckCONTEXT_DestroyPrevDelta(Context));

        gcmkVERIFY_OK(gckOS_QueryNeedCopy(kernel->os, ProcessID, &needCopy));

        uDelta = StateDelta;

        gcmkONERROR(gckKERNEL_OpenUserData(kernel, needCopy, &Context->prevDelta, uDelta,
                                           gcmSIZEOF(gcsSTATE_DELTA), (gctPOINTER *)&kDelta));

        allocated = gcvTRUE;

        dirtyRecordArraySize = gcmSIZEOF(gcsSTATE_DELTA_RECORD) * kDelta->recordCount;

        if (dirtyRecordArraySize) {
            gcmkONERROR(gckOS_Allocate(kernel->os,
                                       gcmSIZEOF(gcsSTATE_DELTA_RECORD) * dirtyRecordArraySize,
                                       &pointer));

            Context->prevRecordArray = (gcsSTATE_DELTA_RECORD_PTR)pointer;

            gcmkONERROR(gckKERNEL_OpenUserData(kernel, needCopy,
                                               Context->prevRecordArray,
                                               gcmUINT64_TO_PTR(kDelta->recordArray),
                                               dirtyRecordArraySize,
                                               (gctPOINTER *)&kRecordArray));

            if (kRecordArray == gcvNULL)
                gcmkONERROR(gcvSTATUS_INVALID_ARGUMENT);

            gcmkONERROR(gckKERNEL_CloseUserData(kernel, needCopy, gcvFALSE,
                                                gcmUINT64_TO_PTR(kDelta->recordArray),
                                                dirtyRecordArraySize,
                                                (gctPOINTER *)&kRecordArray));

        } else {
            Context->prevRecordArray = gcvNULL;
        }

        kDelta->recordArray = gcmPTR_TO_UINT64(Context->prevRecordArray);

        if (Context && Context->maxState > 0) {
            /* Compute UINT array size. */
            gctSIZE_T bytes = Context->maxState * gcmSIZEOF(gctUINT);
            gctUINT32 *kMapEntryID = gcvNULL;
            gctUINT32 *kMapEntryIndex = gcvNULL;

            /* Allocate map ID array. */
            gcmkONERROR(gckOS_Allocate(kernel->os, bytes, &pointer));

            Context->prevMapEntryID = (gctUINT32 *)pointer;

            /* Set the map ID size. */
            kDelta->mapEntryIDSize = (gctUINT32)bytes;

            gcmkONERROR(gckKERNEL_OpenUserData(kernel, needCopy,
                                               Context->prevMapEntryID,
                                               gcmUINT64_TO_PTR(kDelta->mapEntryID),
                                               bytes, (gctPOINTER *)&kMapEntryID));

            if (kMapEntryID == gcvNULL)
                gcmkONERROR(gcvSTATUS_INVALID_ARGUMENT);

            gcmkONERROR(gckKERNEL_CloseUserData(kernel, needCopy, gcvFALSE,
                                                gcmUINT64_TO_PTR(kDelta->mapEntryID),
                                                bytes, (gctPOINTER *)&kMapEntryID));

            kDelta->mapEntryID = gcmPTR_TO_UINT64(Context->prevMapEntryID);

            /* Allocate map index array. */
            gcmkONERROR(gckOS_Allocate(kernel->os, bytes, &pointer));

            Context->prevMapEntryIndex = (gctUINT32 *)pointer;

            gcmkONERROR(gckKERNEL_OpenUserData(kernel, needCopy,
                                               Context->prevMapEntryIndex,
                                               gcmUINT64_TO_PTR(kDelta->mapEntryIndex),
                                               bytes, (gctPOINTER *)&kMapEntryIndex));

            if (kMapEntryIndex == gcvNULL)
                gcmkONERROR(gcvSTATUS_INVALID_ARGUMENT);

            gcmkONERROR(gckKERNEL_CloseUserData(kernel, needCopy, gcvFALSE,
                                                gcmUINT64_TO_PTR(kDelta->mapEntryIndex),
                                                bytes, (gctPOINTER *)&kMapEntryIndex));

            kDelta->mapEntryIndex = gcmPTR_TO_UINT64(Context->prevMapEntryIndex);
        }

        Context->prevDeltaPtr = kDelta;

        gcmkONERROR(gckKERNEL_CloseUserData(kernel, needCopy, gcvFALSE, uDelta,
                                            gcmSIZEOF(gcsSTATE_DELTA), (gctPOINTER *)&kDelta));
    }

    gcmkFOOTER_NO();
    return gcvSTATUS_OK;

OnError:
    if (allocated)
        gcmkVERIFY_OK(gckCONTEXT_DestroyPrevDelta(Context));

    gcmkFOOTER();
    return status;
}

#endif


