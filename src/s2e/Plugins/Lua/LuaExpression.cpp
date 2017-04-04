///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>

#include "LuaExpression.h"

namespace s2e {
namespace plugins {

const char LuaExpression::className[] = "LuaExpression";

Lunar<LuaExpression>::RegType LuaExpression::methods[] = {{0, 0}};
}
}
