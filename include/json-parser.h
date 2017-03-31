/*
 * JSON Parser
 *
 * Copyright IBM, Corp. 2009
 * Copyright 2016 - Cyberhaven
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *  Vitaly Chipounov  <vitaly@cyberhaven.io>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#ifndef QOM_JSON_PARSER_H
#define QOM_JSON_PARSER_H

#include <stdarg.h>
#include "qlist.h"

QObject *json_parser_parse(QList *tokens, va_list *ap);

#endif
