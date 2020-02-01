/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2012, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _ADDRESS_SPACE_NOTIFICATION_H_

#define _ADDRESS_SPACE_NOTIFICATION_H_

#include <vector>
#include "Memory.h"

namespace klee {

class IAddressSpaceNotification {
protected:
    virtual void addressSpaceChange(const ObjectKey &key, const ObjectStateConstPtr &oldState,
                                    const ObjectStatePtr &newState) = 0;

    virtual void addressSpaceObjectSplit(const ObjectStateConstPtr &oldObject,
                                         const std::vector<ObjectStatePtr> &newObjects) = 0;

public:
    virtual ~IAddressSpaceNotification() {
    }
    // Fired whenever an object becomes all concrete or gets at least one symbolic byte.
    // Only fired in the context of a memory operation (load/store)
    virtual void addressSpaceSymbolicStatusChange(const ObjectStatePtr &object, bool becameConcrete) = 0;
};
} // namespace klee

#endif
