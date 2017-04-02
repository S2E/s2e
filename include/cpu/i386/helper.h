/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016  Cyberhaven
/// Copyrights of all contributions belong to their respective owners.
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Library General Public
/// License as published by the Free Software Foundation; either
/// version 2 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Library General Public License for more details.
///
/// You should have received a copy of the GNU Library General Public
/// License along with this library; if not, see <http://www.gnu.org/licenses/>.
///
#ifndef __LIBCPU_I386_HELPER_H__

#define __LIBCPU_I386_HELPER_H__

#define _M_CC_OP (1 << 1)
#define _M_CC_SRC (1 << 2)
#define _M_CC_DST (1 << 3)
#define _M_CC_TMP (1 << 4)
#define _M_EAX (1 << 5)
#define _M_ECX (1 << 6)
#define _M_EDX (1 << 7)
#define _M_EBX (1 << 8)
#define _M_ESP (1 << 9)
#define _M_EBP (1 << 10)
#define _M_ESI (1 << 11)
#define _M_EDI (1 << 12)

#define _M_CC (_M_CC_OP | _M_CC_SRC | _M_CC_DST)

#endif
