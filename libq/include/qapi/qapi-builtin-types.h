/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * Built-in QAPI types
 *
 * Copyright IBM, Corp. 2011
 * Copyright (c) 2013-2018 Red Hat Inc.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#ifndef QAPI_BUILTIN_TYPES_H
#define QAPI_BUILTIN_TYPES_H

#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct QBool QBool;
typedef struct QObject QObject;
typedef struct QNull QNull;
typedef struct QEnumLookup QEnumLookup;

typedef struct strList strList;

typedef struct numberList numberList;

typedef struct intList intList;

typedef struct int8List int8List;

typedef struct int16List int16List;

typedef struct int32List int32List;

typedef struct int64List int64List;

typedef struct uint8List uint8List;

typedef struct uint16List uint16List;

typedef struct uint32List uint32List;

typedef struct uint64List uint64List;

typedef struct sizeList sizeList;

typedef struct boolList boolList;

typedef struct anyList anyList;

typedef struct nullList nullList;

typedef enum QType {
    QTYPE_NONE,
    QTYPE_QNULL,
    QTYPE_QNUM,
    QTYPE_QSTRING,
    QTYPE_QDICT,
    QTYPE_QLIST,
    QTYPE_QBOOL,
    QTYPE__MAX,
} QType;

#define QType_str(val) qapi_enum_lookup(&QType_lookup, (val))

extern const QEnumLookup QType_lookup;

struct strList {
    strList *next;
    char *value;
};

void qapi_free_strList(strList *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(strList, qapi_free_strList)

struct numberList {
    numberList *next;
    double value;
};

void qapi_free_numberList(numberList *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(numberList, qapi_free_numberList)

struct intList {
    intList *next;
    int64_t value;
};

void qapi_free_intList(intList *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(intList, qapi_free_intList)

struct int8List {
    int8List *next;
    int8_t value;
};

void qapi_free_int8List(int8List *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(int8List, qapi_free_int8List)

struct int16List {
    int16List *next;
    int16_t value;
};

void qapi_free_int16List(int16List *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(int16List, qapi_free_int16List)

struct int32List {
    int32List *next;
    int32_t value;
};

void qapi_free_int32List(int32List *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(int32List, qapi_free_int32List)

struct int64List {
    int64List *next;
    int64_t value;
};

void qapi_free_int64List(int64List *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(int64List, qapi_free_int64List)

struct uint8List {
    uint8List *next;
    uint8_t value;
};

void qapi_free_uint8List(uint8List *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(uint8List, qapi_free_uint8List)

struct uint16List {
    uint16List *next;
    uint16_t value;
};

void qapi_free_uint16List(uint16List *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(uint16List, qapi_free_uint16List)

struct uint32List {
    uint32List *next;
    uint32_t value;
};

void qapi_free_uint32List(uint32List *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(uint32List, qapi_free_uint32List)

struct uint64List {
    uint64List *next;
    uint64_t value;
};

void qapi_free_uint64List(uint64List *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(uint64List, qapi_free_uint64List)

struct sizeList {
    sizeList *next;
    uint64_t value;
};

void qapi_free_sizeList(sizeList *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(sizeList, qapi_free_sizeList)

struct boolList {
    boolList *next;
    bool value;
};

void qapi_free_boolList(boolList *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(boolList, qapi_free_boolList)

struct anyList {
    anyList *next;
    QObject *value;
};

void qapi_free_anyList(anyList *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(anyList, qapi_free_anyList)

struct nullList {
    nullList *next;
    QNull *value;
};

void qapi_free_nullList(nullList *obj);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(nullList, qapi_free_nullList)

#ifdef __cplusplus
}
#endif

#endif /* QAPI_BUILTIN_TYPES_H */
