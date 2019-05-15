/*++

Copyright (c) 2001 Microsoft Corporation

Module Name:

    avltable.h

Abstract:
    Contains functions supporting AVL table operations.

Author:
    Jay Lorch (lorch) 5-Oct-2012

--*/

#ifndef _AVLTABLE_
#define _AVLTABLE_
#pragma once

VOID
NTAPI
AvlInitializeGenericTableAvl (
    __out PRTL_AVL_TABLE Table,
    __in PRTL_AVL_COMPARE_ROUTINE CompareRoutine,
    __in PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine,
    __in PRTL_AVL_FREE_ROUTINE FreeRoutine,
    __in_opt PVOID TableContext
    );

PVOID
AvlInsertElementGenericTableAvl (
    __in PRTL_AVL_TABLE Table,
    __in_bcount(BufferSize) PVOID Buffer,
    __in CLONG BufferSize,
    __out_opt PBOOLEAN NewElement
    );

PVOID
AvlInsertElementGenericTableFullAvl (
    __in PRTL_AVL_TABLE Table,
    __in_bcount(BufferSize) PVOID Buffer,
    __in CLONG BufferSize,
    __out_opt PBOOLEAN NewElement,
    __in PVOID NodeOrParent,
    __in TABLE_SEARCH_RESULT SearchResult
    );

BOOLEAN
AvlDeleteElementGenericTableAvl (
    __in PRTL_AVL_TABLE Table,
    __in PVOID Buffer
    );

PVOID
AvlLookupElementGenericTableAvl (
    __in PRTL_AVL_TABLE Table,
    __in PVOID Buffer
    );

PVOID
NTAPI
AvlLookupElementGenericTableFullAvl (
    __in PRTL_AVL_TABLE Table,
    __in PVOID Buffer,
    __out PVOID *NodeOrParent,
    __out TABLE_SEARCH_RESULT *SearchResult
    );

PVOID
AvlEnumerateGenericTableAvl (
    __in PRTL_AVL_TABLE Table,
    __in BOOLEAN Restart
    );

BOOLEAN
AvlIsGenericTableEmptyAvl (
    __in PRTL_AVL_TABLE Table
    );

PVOID
AvlGetElementGenericTableAvl (
    __in PRTL_AVL_TABLE Table,
    __in ULONG I
    );

ULONG
AvlNumberGenericTableElementsAvl (
    __in PRTL_AVL_TABLE Table
    );

PVOID
AvlEnumerateGenericTableWithoutSplayingAvl (
    __in PRTL_AVL_TABLE Table,
    __inout PVOID *RestartKey
    );

PVOID
NTAPI
AvlEnumerateGenericTableLikeADirectory (
    __in PRTL_AVL_TABLE Table,
    __in_opt PRTL_AVL_MATCH_FUNCTION MatchFunction,
    __in_opt PVOID MatchData,
    __in ULONG NextFlag,
    __inout PVOID *RestartKey,
    __inout PULONG DeleteCount,
    __in PVOID Buffer
    );

PVOID
NTAPI
AvlLookupFirstMatchingElementGenericTableAvl (
    __in PRTL_AVL_TABLE Table,
    __in PVOID Buffer,
    __out PVOID *RestartKey
    );

//
// The following callback and function allow the AVL table to be
// efficiently enumerated. (contributed by Jay Lorch)
//

typedef
NTSTATUS
(*AVL_GENERIC_TABLE_NODE_CALLBACK)(
    __in PVOID CallbackParameters,
    __in PVOID NodeDataPtr
    );

NTSTATUS
AvlEnumerateGenericTableWithCallback(
    __in PRTL_AVL_TABLE Table,
    __in AVL_GENERIC_TABLE_NODE_CALLBACK Callback,
    __in PVOID CallbackParameters
    );

#endif // _AVLTABLE_