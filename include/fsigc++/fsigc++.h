/// Copyright (c) 2017 Cyberhaven
/// Copyright (c) 2011 Dependable Systems Lab, EPFL
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef _S2E_SIGNALS_

#define _S2E_SIGNALS_

//#define FASSERT assert
#define FASSERT(x)

#include <cassert>
#include <stdlib.h>
#include <string.h>

#define fsigc sigc

namespace fsigc {

class trackable {};

struct nil {};

class mysignal_base;

class connection {
private:
    void *m_functor;
    mysignal_base *m_sig;
    bool m_connected;

public:
    connection() {
        m_functor = NULL;
        m_sig = NULL;
        m_connected = false;
    }

    connection(mysignal_base *sig, void *func);
    inline bool connected() const {
        return m_connected;
    }
    void disconnect();
};

class mysignal_base {
public:
    virtual ~mysignal_base() {
    }
    virtual void disconnect(void *functor) = 0;
};

//*************************************************
//*************************************************
//*************************************************

template <typename RET, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7>
class functor_base {
protected:
    unsigned m_refcount;

public:
    functor_base() : m_refcount(0) {
    }
    void incref() {
        ++m_refcount;
    }
    unsigned decref() {
        assert(this->m_refcount > 0);
        return --m_refcount;
    }
    virtual ~functor_base() {
        assert(m_refcount == 0);
    }
    virtual RET operator()() {
        assert(false);
    };
    virtual RET operator()(P1 p1) {
        assert(false);
    };
    virtual RET operator()(P1 p1, P2 p2) {
        assert(false);
    };
    virtual RET operator()(P1 p1, P2 p2, P3 p3) {
        assert(false);
    };
    virtual RET operator()(P1 p1, P2 p2, P3 p3, P4 p4) {
        assert(false);
    };
    virtual RET operator()(P1 p1, P2 p2, P3 p3, P4 p4, P5 p5) {
        assert(false);
    };
    virtual RET operator()(P1 p1, P2 p2, P3 p3, P4 p4, P5 p5, P6 p6) {
        assert(false);
    };
    virtual RET operator()(P1 p1, P2 p2, P3 p3, P4 p4, P5 p5, P6 p6, P7 p7) {
        assert(false);
    };
};

//*************************************************
// Stateless function pointers
// 0 parameter
//*************************************************
template <typename RET> class ptrfun0 : public functor_base<RET, nil, nil, nil, nil, nil, nil, nil> {
public:
    typedef RET (*func_t)();

protected:
    func_t m_func;

public:
    ptrfun0(func_t f) {
        m_func = f;
    };

    virtual ~ptrfun0() {
    }

    virtual RET operator()() {
        FASSERT(this->m_refcount > 0);
        return (*m_func)();
    };
};

template <typename RET> inline functor_base<RET, nil, nil, nil, nil, nil, nil, nil> *ptr_fun(RET (*f)()) {
    return new ptrfun0<RET>(f);
}

//*************************************************
//*************************************************
//*************************************************

//*************************************************
// 0 parameter
//*************************************************
template <class T, typename RET> class functor0 : public functor_base<RET, nil, nil, nil, nil, nil, nil, nil> {
public:
    typedef RET (T::*func_t)();

protected:
    func_t m_func;
    T *m_obj;

public:
    functor0(T *obj, func_t f) {
        m_obj = obj;
        m_func = f;
    };

    virtual ~functor0() {
    }

    virtual RET operator()() {
        FASSERT(this->m_refcount > 0);
        return (*m_obj.*m_func)();
    };
};

template <class T, typename RET>
inline functor_base<RET, nil, nil, nil, nil, nil, nil, nil> *mem_fun(T &obj, RET (T::*f)()) {
    return new functor0<T, RET>(&obj, f);
}

#define SIGNAL_CLASS signal0
#define OPERATOR_PARAM_DECL
#define CALL_PARAMS

template <typename RET> class SIGNAL_CLASS : public mysignal_base {
public:
    typedef functor_base<RET, nil, nil, nil, nil, nil, nil, nil> *func_t;
#include "sig-template.h"
};

#undef CALL_PARAMS
#undef OPERATOR_PARAM_DECL
#undef SIGNAL_CLASS

//*************************************************
// 1 parameter
//*************************************************

#define FUNCTOR_NAME functor1
#define TYPENAMES typename P1
#define BASE_CLASS_INST P1, nil, nil, nil, nil, nil, nil
#define FUNCT_DECL P1
#define OPERATOR_PARAM_DECL P1 p1
#define CALL_PARAMS p1
#define SIGNAL_CLASS signal1

#include "functors.h"

template <typename RET, TYPENAMES> class SIGNAL_CLASS : public mysignal_base {
public:
    typedef functor_base<RET, BASE_CLASS_INST> *func_t;
#include "sig-template.h"
};

//*************************************************
// 2 parameters
//*************************************************

#define FUNCTOR_NAME functor2
#define TYPENAMES typename P1, typename P2
#define BASE_CLASS_INST P1, P2, nil, nil, nil, nil, nil
#define FUNCT_DECL P1, P2
#define OPERATOR_PARAM_DECL P1 p1, P2 p2
#define CALL_PARAMS p1, p2
#define SIGNAL_CLASS signal2

#include "functors.h"

template <typename RET, TYPENAMES> class SIGNAL_CLASS : public mysignal_base {
public:
    typedef functor_base<RET, BASE_CLASS_INST> *func_t;
#include "sig-template.h"
};

//*************************************************
// 3 parameters
//*************************************************

#define FUNCTOR_NAME functor3
#define TYPENAMES typename P1, typename P2, typename P3
#define BASE_CLASS_INST P1, P2, P3, nil, nil, nil, nil
#define FUNCT_DECL P1, P2, P3
#define OPERATOR_PARAM_DECL P1 p1, P2 p2, P3 p3
#define CALL_PARAMS p1, p2, p3
#define SIGNAL_CLASS signal3

#include "functors.h"

template <typename RET, TYPENAMES> class SIGNAL_CLASS : public mysignal_base {
public:
    typedef functor_base<RET, BASE_CLASS_INST> *func_t;
#include "sig-template.h"
};

//*************************************************
// 4 parameters
//*************************************************

#define FUNCTOR_NAME functor4
#define TYPENAMES typename P1, typename P2, typename P3, typename P4
#define BASE_CLASS_INST P1, P2, P3, P4, nil, nil, nil
#define FUNCT_DECL P1, P2, P3, P4
#define OPERATOR_PARAM_DECL P1 p1, P2 p2, P3 p3, P4 p4
#define CALL_PARAMS p1, p2, p3, p4
#define SIGNAL_CLASS signal4

#include "functors.h"

template <typename RET, TYPENAMES> class SIGNAL_CLASS : public mysignal_base {
public:
    typedef functor_base<RET, BASE_CLASS_INST> *func_t;
#include "sig-template.h"
};

//*************************************************
// 5 parameters
//*************************************************

#define FUNCTOR_NAME functor5
#define TYPENAMES typename P1, typename P2, typename P3, typename P4, typename P5
#define BASE_CLASS_INST P1, P2, P3, P4, P5, nil, nil
#define FUNCT_DECL P1, P2, P3, P4, P5
#define OPERATOR_PARAM_DECL P1 p1, P2 p2, P3 p3, P4 p4, P5 p5
#define CALL_PARAMS p1, p2, p3, p4, p5
#define SIGNAL_CLASS signal5

#include "functors.h"

template <typename RET, TYPENAMES> class SIGNAL_CLASS : public mysignal_base {
public:
    typedef functor_base<RET, BASE_CLASS_INST> *func_t;
#include "sig-template.h"
};

//*************************************************
// 6 parameters
//*************************************************

#define FUNCTOR_NAME functor6
#define TYPENAMES typename P1, typename P2, typename P3, typename P4, typename P5, typename P6
#define BASE_CLASS_INST P1, P2, P3, P4, P5, P6, nil
#define FUNCT_DECL P1, P2, P3, P4, P5, P6
#define OPERATOR_PARAM_DECL P1 p1, P2 p2, P3 p3, P4 p4, P5 p5, P6 p6
#define CALL_PARAMS p1, p2, p3, p4, p5, p6
#define SIGNAL_CLASS signal6

#include "functors.h"

template <typename RET, TYPENAMES> class SIGNAL_CLASS : public mysignal_base {
public:
    typedef functor_base<RET, BASE_CLASS_INST> *func_t;
#include "sig-template.h"
};

//*************************************************
// 7 parameters
//*************************************************

#define FUNCTOR_NAME functor7
#define TYPENAMES typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7
#define BASE_CLASS_INST P1, P2, P3, P4, P5, P6, P7
#define FUNCT_DECL P1, P2, P3, P4, P5, P6, P7
#define OPERATOR_PARAM_DECL P1 p1, P2 p2, P3 p3, P4 p4, P5 p5, P6 p6, P7 p7
#define CALL_PARAMS p1, p2, p3, p4, p5, p6, p7
#define SIGNAL_CLASS signal7

#include "functors.h"

template <typename RET, TYPENAMES> class SIGNAL_CLASS : public mysignal_base {
public:
    typedef functor_base<RET, BASE_CLASS_INST> *func_t;
#include "sig-template.h"
};

//*************************************************
//*************************************************
//*************************************************

// Binders

//*************************************************
// 0 arguments base event - 1 extra argument
template <typename RET, typename A1, typename B1>
class functor0_1 : public functor_base<RET, nil, nil, nil, nil, nil, nil, nil> {
public:
    typedef functor_base<RET, A1, nil, nil, nil, nil, nil, nil> functor_t;

private:
    functor_t *m_fb;
    A1 a1;

public:
    functor0_1(functor_t *fb, A1 _a1) : m_fb(fb), a1(_a1) {
        fb->incref();
    }
    virtual ~functor0_1() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }

    virtual RET operator()() {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(a1);
    };
};

template <typename RET, typename A1, typename B1>
inline functor_base<RET, nil, nil, nil, nil, nil, nil, nil> *
bind(functor_base<RET, A1, nil, nil, nil, nil, nil, nil> *f, B1 a1) {
    return new functor0_1<RET, A1, B1>(f, a1);
}

// 0 arguments base event - 2 extra argument
template <typename RET, typename A1, typename A2>
class functor0_2 : public functor_base<RET, nil, nil, nil, nil, nil, nil, nil> {
public:
    typedef functor_base<RET, A1, A2, nil, nil, nil, nil, nil> functor_t;

private:
    functor_t *m_fb;
    A1 a1;
    A2 a2;

public:
    functor0_2(functor_t *fb, A1 a1_, A2 a2_) : m_fb(fb), a1(a1_), a2(a2_) {
        m_fb->incref();
    }
    virtual ~functor0_2() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }

    virtual RET operator()() {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(a1, a2);
    };
};

template <typename RET, typename A1, typename B1, typename A2, typename B2>
inline functor_base<RET, nil, nil, nil, nil, nil, nil, nil> *bind(functor_base<RET, A1, A2, nil, nil, nil, nil, nil> *f,
                                                                  B1 a1, B2 a2) {
    return new functor0_2<RET, A1, A2>(f, a1, a2);
}

//*************************************************
// 1 arguments base event - 1 extra argument
template <typename RET, typename BE1, typename A1>
class functor1_1 : public functor_base<RET, BE1, nil, nil, nil, nil, nil, nil> {
public:
    typedef functor_base<RET, BE1, A1, nil, nil, nil, nil, nil> functor_t;

private:
    functor_t *m_fb;
    A1 a1;

public:
    functor1_1(functor_t *fb, A1 a1_) : m_fb(fb), a1(a1_) {
        m_fb->incref();
    }
    virtual ~functor1_1() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }
    virtual RET operator()(BE1 be1) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(be1, a1);
    };
};

template <typename RET, typename BE1, typename A1, typename B1>
inline functor_base<RET, BE1, nil, nil, nil, nil, nil, nil> *
bind(functor_base<RET, BE1, A1, nil, nil, nil, nil, nil> *f, B1 a1) {
    return new functor1_1<RET, BE1, A1>(f, a1);
}

// 1 arguments base event - 2 extra argument
template <typename RET, typename BE1, typename A1, typename A2>
class functor1_2 : public functor_base<RET, BE1, nil, nil, nil, nil, nil, nil> {
public:
    typedef functor_base<RET, BE1, A1, A2, nil, nil, nil, nil> functor_t;

private:
    functor_t *m_fb;
    A1 a1;
    A2 a2;

public:
    functor1_2(functor_t *fb, A1 a1_, A2 a2_) : m_fb(fb), a1(a1_), a2(a2_) {
        m_fb->incref();
    }
    virtual ~functor1_2() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }
    virtual RET operator()(BE1 be1) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(be1, a1, a2);
    };
};

template <typename RET, typename BE1, typename A1, typename B1, typename A2, typename B2>
inline functor_base<RET, BE1, nil, nil, nil, nil, nil, nil> *bind(functor_base<RET, BE1, A1, A2, nil, nil, nil, nil> *f,
                                                                  B1 a1, B2 a2) {
    return new functor1_2<RET, BE1, A1, A2>(f, a1, a2);
}

// 1 arguments base event - 3 extra argument
template <typename RET, typename BE1, typename A1, typename A2, typename A3>
class functor1_3 : public functor_base<RET, BE1, nil, nil, nil, nil, nil, nil> {
public:
    typedef functor_base<RET, BE1, A1, A2, A3, nil, nil, nil> functor_t;

private:
    functor_t *m_fb;
    A1 a1;
    A2 a2;
    A3 a3;

public:
    functor1_3(functor_t *fb, A1 a1_, A2 a2_, A3 a3_) : m_fb(fb), a1(a1_), a2(a2_), a3(a3_) {
        m_fb->incref();
    }
    virtual ~functor1_3() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }
    virtual RET operator()(BE1 be1) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(be1, a1, a2, a3);
    };
};

template <typename RET, typename BE1, typename A1, typename B1, typename A2, typename B2, typename A3, typename B3>
inline functor_base<RET, BE1, nil, nil, nil, nil, nil, nil> *bind(functor_base<RET, BE1, A1, A2, A3, nil, nil, nil> *f,
                                                                  B1 a1, B2 a2, B3 a3) {
    return new functor1_3<RET, BE1, A1, A2, A3>(f, a1, a2, a3);
}

// 1 arguments base event - 4 extra argument
template <typename RET, typename BE1, typename A1, typename A2, typename A3, typename A4>
class functor1_4 : public functor_base<RET, BE1, nil, nil, nil, nil, nil, nil> {
public:
    typedef functor_base<RET, BE1, A1, A2, A3, A4, nil, nil> functor_t;

private:
    functor_t *m_fb;
    A1 a1;
    A2 a2;
    A3 a3;
    A4 a4;

public:
    functor1_4(functor_t *fb, A1 a1_, A2 a2_, A3 a3_, A4 a4_) : m_fb(fb), a1(a1_), a2(a2_), a3(a3_), a4(a4_) {
        m_fb->incref();
    }
    virtual ~functor1_4() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }
    virtual RET operator()(BE1 be1) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(be1, a1, a2, a3, a4);
    };
};

template <typename RET, typename BE1, typename A1, typename B1, typename A2, typename B2, typename A3, typename B3,
          typename A4, typename B4>
inline functor_base<RET, BE1, nil, nil, nil, nil, nil, nil> *bind(functor_base<RET, BE1, A1, A2, A3, A4, nil, nil> *f,
                                                                  B1 a1, B2 a2, B3 a3, B4 a4) {
    return new functor1_4<RET, BE1, A1, A2, A3, A4>(f, a1, a2, a3, a4);
}

//*************************************************
// 2 arguments base event - 1 extra argument
template <typename RET, typename BE1, typename BE2, typename A1>
class functor2_1 : public functor_base<RET, BE1, BE2, nil, nil, nil, nil, nil> {
public:
    typedef functor_base<RET, BE1, BE2, A1, nil, nil, nil, nil> functor_t;

private:
    functor_t *m_fb;
    A1 a1;

public:
    functor2_1(functor_t *fb, A1 a1_) : m_fb(fb), a1(a1_) {
        m_fb->incref();
    }
    virtual ~functor2_1() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }
    virtual RET operator()(BE1 be1, BE2 be2) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(be1, be2, a1);
    };
};

template <typename RET, typename BE1, typename BE2, typename A1, typename B1>
inline functor_base<RET, BE1, BE2, nil, nil, nil, nil, nil> *
bind(functor_base<RET, BE1, BE2, A1, nil, nil, nil, nil> *f, B1 a1) {
    return new functor2_1<RET, BE1, BE2, A1>(f, a1);
}

// 2 arguments base event - 2 extra argument
template <typename RET, typename BE1, typename BE2, typename A1, typename A2>
class functor2_2 : public functor_base<RET, BE1, BE2, nil, nil, nil, nil, nil> {
public:
    typedef functor_base<RET, BE1, BE2, A1, A2, nil, nil, nil> functor_t;

private:
    functor_t *m_fb;
    A1 a1;
    A2 a2;

public:
    functor2_2(functor_t *fb, A1 a1_, A2 a2_) : m_fb(fb), a1(a1_), a2(a2_) {
        m_fb->incref();
    }
    virtual ~functor2_2() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }
    virtual RET operator()(BE1 be1, BE2 be2) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(be1, be2, a1, a2);
    };
};

template <typename RET, typename BE1, typename BE2, typename A1, typename B1, typename A2, typename B2>
inline functor_base<RET, BE1, BE2, nil, nil, nil, nil, nil> *bind(functor_base<RET, BE1, BE2, A1, A2, nil, nil, nil> *f,
                                                                  B1 a1, B2 a2) {
    return new functor2_2<RET, BE1, BE2, A1, A2>(f, a1, a2);
}

// 2 arguments base event - 3 extra argument
template <typename RET, typename BE1, typename BE2, typename A1, typename A2, typename A3>
class functor2_3 : public functor_base<RET, BE1, BE2, nil, nil, nil, nil, nil> {
public:
    typedef functor_base<RET, BE1, BE2, A1, A2, A3, nil, nil> functor_t;

private:
    functor_t *m_fb;
    A1 a1;
    A2 a2;
    A3 a3;

public:
    functor2_3(functor_t *fb, A1 a1_, A2 a2_, A3 a3_) : m_fb(fb), a1(a1_), a2(a2_), a3(a3_) {
        m_fb->incref();
    }
    virtual ~functor2_3() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }
    virtual RET operator()(BE1 be1, BE2 be2) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(be1, be2, a1, a2, a3);
    };
};

template <typename RET, typename BE1, typename BE2, typename A1, typename B1, typename A2, typename B2, typename A3,
          typename B3>
inline functor_base<RET, BE1, BE2, nil, nil, nil, nil, nil> *bind(functor_base<RET, BE1, BE2, A1, A2, A3, nil, nil> *f,
                                                                  B1 a1, B2 a2, B3 a3) {
    return new functor2_3<RET, BE1, BE2, A1, A2, A3>(f, a1, a2, a3);
}

//*************************************************
// 3 arguments base event - 1 extra argument
template <typename RET, typename BE1, typename BE2, typename BE3, typename A1>
class functor3_1 : public functor_base<RET, BE1, BE2, BE3, nil, nil, nil, nil> {
public:
    typedef functor_base<RET, BE1, BE2, BE3, A1, nil, nil, nil> functor_t;

private:
    functor_t *m_fb;
    A1 a1;

public:
    functor3_1(functor_t *fb, A1 a1_) : m_fb(fb), a1(a1_) {
        m_fb->incref();
    }
    virtual ~functor3_1() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }
    virtual RET operator()(BE1 be1, BE2 be2, BE3 be3) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(be1, be2, be3, a1);
    };
};

template <typename RET, typename BE1, typename BE2, typename BE3, typename A1, typename B1>
inline functor_base<RET, BE1, BE2, BE3, nil, nil, nil, nil> *
bind(functor_base<RET, BE1, BE2, BE3, A1, nil, nil, nil> *f, B1 a1) {
    return new functor3_1<RET, BE1, BE2, BE3, A1>(f, a1);
}

// 3 arguments base event - 2 extra argument
template <typename RET, typename BE1, typename BE2, typename BE3, typename A1, typename A2>
class functor3_2 : public functor_base<RET, BE1, BE2, BE3, nil, nil, nil, nil> {
public:
    typedef functor_base<RET, BE1, BE2, BE3, A1, A2, nil, nil> functor_t;

private:
    functor_t *m_fb;
    A1 a1;
    A2 a2;

public:
    functor3_2(functor_t *fb, A1 a1_, A2 a2_) : m_fb(fb), a1(a1_), a2(a2_) {
        m_fb->incref();
    }
    virtual ~functor3_2() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }
    virtual RET operator()(BE1 be1, BE2 be2, BE3 be3) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(be1, be2, be3, a1, a2);
    };
};

template <typename RET, typename BE1, typename BE2, typename BE3, typename A1, typename B1, typename A2, typename B2>
inline functor_base<RET, BE1, BE2, BE3, nil, nil, nil, nil> *bind(functor_base<RET, BE1, BE2, BE3, A1, A2, nil, nil> *f,
                                                                  B1 a1, B2 a2) {
    return new functor3_2<RET, BE1, BE2, BE3, A1, A2>(f, a1, a2);
}

//*************************************************
// 4 arguments base event - 1 extra argument
template <typename RET, typename BE1, typename BE2, typename BE3, typename BE4, typename A1>
class functor4_1 : public functor_base<RET, BE1, BE2, BE3, BE4, nil, nil, nil> {
public:
    typedef functor_base<RET, BE1, BE2, BE3, BE4, A1, nil, nil> functor_t;

private:
    functor_t *m_fb;
    A1 a1;

public:
    functor4_1(functor_t *fb, A1 a1_) : m_fb(fb), a1(a1_) {
        m_fb->incref();
    }
    virtual ~functor4_1() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }
    virtual RET operator()(BE1 be1, BE2 be2, BE3 be3, BE4 be4) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(be1, be2, be3, be4, a1);
    };
};

template <typename RET, typename BE1, typename BE2, typename BE3, typename BE4, typename A1, typename B1>
inline functor_base<RET, BE1, BE2, BE3, BE4, nil, nil, nil> *
bind(functor_base<RET, BE1, BE2, BE3, BE4, A1, nil, nil> *f, B1 a1) {
    return new functor4_1<RET, BE1, BE2, BE3, BE4, A1>(f, a1);
}

// 4 arguments base event - 2 extra argument
template <typename RET, typename BE1, typename BE2, typename BE3, typename BE4, typename A1, typename A2>
class functor4_2 : public functor_base<RET, BE1, BE2, BE3, BE4, nil, nil, nil> {
public:
    typedef functor_base<RET, BE1, BE2, BE3, BE4, A1, A2, nil> functor_t;

private:
    functor_t *m_fb;
    A1 a1;
    A2 a2;

public:
    functor4_2(functor_t *fb, A1 a1_, A2 a2_) : m_fb(fb), a1(a1_), a2(a2_) {
        m_fb->incref();
    }
    virtual ~functor4_2() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }
    virtual RET operator()(BE1 be1, BE2 be2, BE3 be3, BE4 be4) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(be1, be2, be3, be4, a1, a2);
    };
};

template <typename RET, typename BE1, typename BE2, typename BE3, typename BE4, typename A1, typename B1, typename A2,
          typename B2>
inline functor_base<RET, BE1, BE2, BE3, BE4, nil, nil, nil> *bind(functor_base<RET, BE1, BE2, BE3, BE4, A1, A2, nil> *f,
                                                                  B1 a1, B2 a2) {
    return new functor4_2<RET, BE1, BE2, BE3, BE4, A1, A2>(f, a1, a2);
}

// 4 arguments base event - 3 extra argument
template <typename RET, typename BE1, typename BE2, typename BE3, typename BE4, typename A1, typename A2, typename A3>
class functor4_3 : public functor_base<RET, BE1, BE2, BE3, BE4, nil, nil, nil> {
public:
    typedef functor_base<RET, BE1, BE2, BE3, BE4, A1, A2, A3> functor_t;

private:
    functor_t *m_fb;
    A1 a1;
    A2 a2;
    A3 a3;

public:
    functor4_3(functor_t *fb, A1 a1_, A2 a2_, A3 a3_) : m_fb(fb), a1(a1_), a2(a2_), a3(a3_) {
        m_fb->incref();
    }
    virtual ~functor4_3() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }
    virtual RET operator()(BE1 be1, BE2 be2, BE3 be3, BE4 be4) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(be1, be2, be3, be4, a1, a2, a3);
    };
};

template <typename RET, typename BE1, typename BE2, typename BE3, typename BE4, typename A1, typename B1, typename A2,
          typename B2, typename A3, typename B3>
inline functor_base<RET, BE1, BE2, BE3, BE4, nil, nil, nil> *bind(functor_base<RET, BE1, BE2, BE3, BE4, A1, A2, A3> *f,
                                                                  B1 a1, B2 a2, B3 a3) {
    return new functor4_3<RET, BE1, BE2, BE3, BE4, A1, A2, A3>(f, a1, a2, a3);
}

//*************************************************
//*************************************************
//*************************************************

template <typename RET, typename P1 = nil, typename P2 = nil, typename P3 = nil, typename P4 = nil, typename P5 = nil,
          typename P6 = nil, typename P7 = nil>
class signal : public signal7<RET, P1, P2, P3, P4, P5, P6, P7> {};

template <typename RET, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6>
class signal<RET, P1, P2, P3, P4, P5, P6> : public signal6<RET, P1, P2, P3, P4, P5, P6> {};

template <typename RET, typename P1, typename P2, typename P3, typename P4, typename P5>
class signal<RET, P1, P2, P3, P4, P5> : public signal5<RET, P1, P2, P3, P4, P5> {};

template <typename RET, typename P1, typename P2, typename P3, typename P4>
class signal<RET, P1, P2, P3, P4> : public signal4<RET, P1, P2, P3, P4> {};

template <typename RET, typename P1, typename P2, typename P3>
class signal<RET, P1, P2, P3> : public signal3<RET, P1, P2, P3> {};

template <typename RET, typename P1, typename P2> class signal<RET, P1, P2> : public signal2<RET, P1, P2> {};

template <typename RET, typename P1> class signal<RET, P1> : public signal1<RET, P1> {};

template <typename RET> class signal<RET> : public signal0<RET> {};
}

#endif
