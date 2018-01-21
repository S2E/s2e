///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#pragma once

// Disable static analysis macros when ReSharper is used to reformat the code.
// - specstrings_strict.h checks _PREFAST_ to define _Outptr_
// - specstrings.h checks _Outptr_ to use no_sal2.h
#ifdef __RESHARPER__
#define _PREFAST_
#endif
