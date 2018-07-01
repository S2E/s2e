/// Copyright (c) 2017-2018 Cyberhaven
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

#include <cassert>
#include <stdlib.h>
#include <vector>

//#define FASSERT assert
#define FASSERT(x)
#define fsigc sigc

namespace fsigc {

class signal_base {
public:
    // Indicative priority levels that can be used to connect signals
    static const int HIGHEST_PRIORITY = 10;
    static const int HIGH_PRIORITY = 5;
    static const int MEDIUM_PRIORITY = 0;
    static const int LOW_PRIORITY = -5;
    static const int LOWEST_PRIORITY = -10;

    virtual ~signal_base() {
    }

    virtual void disconnect(void *functor) = 0;
};

class connection {
private:
    void *m_functor;
    signal_base *m_sig;
    bool m_connected;

public:
    connection() {
        m_functor = NULL;
        m_sig = NULL;
        m_connected = false;
    }

    connection(signal_base *sig, void *func);
    inline bool connected() const {
        return m_connected;
    }
    void disconnect();
};

//*************************************************
//*************************************************
//*************************************************

template <typename RET, typename... PARAM_TYPES> class functor_base {
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
    virtual RET operator()(PARAM_TYPES... params) {
        assert(false);
    }
};

//*************************************************
// Stateless function pointers
//*************************************************
template <typename RET, typename... PARAM_TYPES> class ptrfunn : public functor_base<RET, PARAM_TYPES...> {
public:
    typedef RET (*func_t)(PARAM_TYPES...);

protected:
    func_t m_func;

public:
    ptrfunn(func_t f) {
        m_func = f;
    }

    virtual ~ptrfunn() {
    }

    virtual RET operator()(PARAM_TYPES... types) {
        FASSERT(this->m_refcount > 0);
        return (*m_func)(types...);
    }
};

template <typename RET, typename... PARAM_TYPES>
inline functor_base<RET, PARAM_TYPES...> *ptr_fun(RET (*f)(PARAM_TYPES...)) {
    return new ptrfunn<RET, PARAM_TYPES...>(f);
}

//*************************************************
//*************************************************
//*************************************************

//*************************************************
// n parameter
//*************************************************
template <class T, typename RET, typename... PARAM_TYPES> class functorn : public functor_base<RET, PARAM_TYPES...> {
public:
    typedef RET (T::*func_t)(PARAM_TYPES...);

protected:
    func_t m_func;
    T *m_obj;

public:
    functorn(T *obj, func_t f) {
        m_obj = obj;
        m_func = f;
    }

    virtual ~functorn() {
    }

    virtual RET operator()(PARAM_TYPES... types) {
        FASSERT(this->m_refcount > 0);
        return (*m_obj.*m_func)(types...);
    }
};

template <class T, typename RET, typename... PARAM_TYPES>
inline functor_base<RET, PARAM_TYPES...> *mem_fun(T &obj, RET (T::*f)(PARAM_TYPES...)) {
    return new functorn<T, RET, PARAM_TYPES...>(&obj, f);
}

template <typename RET, typename... PARAM_TYPES> class signal : public signal_base {
public:
    typedef functor_base<RET, PARAM_TYPES...> *func_t;

    unsigned m_activeSignals;

private:
    // Each signal has a priority. Any new signal will be inserted
    // in the list according to its priority.
    // Higher priorities go first in the list.
    typedef std::pair<func_t, int> func_priority_t;
    std::vector<func_priority_t> m_funcs;

    void disconnectAll() {
        for (auto &it : m_funcs) {
            if (it.first && !it.first->decref()) {
                delete it.first;
                it.first = nullptr;
            }
        }
        m_funcs.clear();
    }

public:
    signal() {
        m_activeSignals = 0;
    }

    signal(const signal &one) {
        m_activeSignals = one.m_activeSignals;
        m_funcs = one.m_funcs;

        for (auto &it : m_funcs) {
            if (it.first) {
                it.first->incref();
            }
        }
    }

    virtual ~signal() {
        disconnectAll();
    }

    virtual void disconnect(void *functor) {
        assert(m_activeSignals > 0);

        for (auto it = m_funcs.begin(); it != m_funcs.end(); ++it) {
            auto fcn = (*it).first;
            if (fcn == functor) {
                if (!fcn->decref()) {
                    delete fcn;
                }
                --m_activeSignals;
                m_funcs.erase(it);
                break;
            }
        }
    }

    connection connect(func_t fcn, int priority = MEDIUM_PRIORITY) {
        fcn->incref();
        ++m_activeSignals;
        auto p = func_priority_t(fcn, priority);

        for (auto it = m_funcs.begin(); it != m_funcs.end(); ++it) {
            if ((*it).second < priority) {
                m_funcs.insert(it, p);
                return connection(this, fcn);
            }
        }

        m_funcs.push_back(p);
        return connection(this, fcn);
    }

    bool empty() const {
        return m_funcs.size() == 0;
    }

    void emit(PARAM_TYPES... params) {
        for (auto &it : m_funcs) {
            it.first->operator()(params...);
        }
    }

    // This is intended for optimization purposes only.
    // The softmmu code needs to check whether there are signals registered
    // for memory tracing. To avoid going through several layers of code,
    // this function returns a pointer to the internal field.
    unsigned *getActiveSignalsPtr() {
        return &m_activeSignals;
    }
};

// TODO: there is still code duplication in functorn_x functions.
// See if some C++ template magic can fix this.
// The problem is that it's not possible to have multiple variadic params.

template <typename RET, typename A1, typename... PARAM_TYPES>
class functorn_1 : public functor_base<RET, PARAM_TYPES...> {
public:
    typedef functor_base<RET, PARAM_TYPES..., A1> functor_t;

private:
    functor_t *m_fb;
    A1 a1;

public:
    functorn_1(functor_t *fb, A1 _a1) : m_fb(fb), a1(_a1) {
        fb->incref();
    }
    virtual ~functorn_1() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }

    virtual RET operator()(PARAM_TYPES... params) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(params..., a1);
    }
};

template <typename RET, typename A1, typename A2, typename... PARAM_TYPES>
class functorn_2 : public functor_base<RET, PARAM_TYPES...> {
public:
    typedef functor_base<RET, PARAM_TYPES..., A1, A2> functor_t;

private:
    functor_t *m_fb;
    A1 a1;
    A2 a2;

public:
    functorn_2(functor_t *fb, A1 _a1, A2 _a2) : m_fb(fb), a1(_a1), a2(_a2) {
        fb->incref();
    }
    virtual ~functorn_2() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }

    virtual RET operator()(PARAM_TYPES... params) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(params..., a1, a2);
    }
};

template <typename RET, typename A1, typename A2, typename A3, typename... PARAM_TYPES>
class functorn_3 : public functor_base<RET, PARAM_TYPES...> {
public:
    typedef functor_base<RET, PARAM_TYPES..., A1, A2, A3> functor_t;

private:
    functor_t *m_fb;
    A1 a1;
    A2 a2;
    A3 a3;

public:
    functorn_3(functor_t *fb, A1 _a1, A2 _a2, A3 _a3) : m_fb(fb), a1(_a1), a2(_a2), a3(_a3) {
        fb->incref();
    }

    virtual ~functorn_3() {
        if (!m_fb->decref()) {
            delete m_fb;
        }
    }

    virtual RET operator()(PARAM_TYPES... params) {
        FASSERT(this->m_refcount > 0);
        return m_fb->operator()(params..., a1, a2, a3);
    }
};

// 0 arguments base event - 1 extra argument
template <typename RET, typename A1, typename B1> inline functor_base<RET> *bind(functor_base<RET, A1> *f, B1 a1) {
    return new functorn_1<RET, A1>(f, a1);
}

// 0 arguments base event - 2 extra arguments
template <typename RET, typename A1, typename B1, typename A2, typename B2>
inline functor_base<RET> *bind(functor_base<RET, A1, A2> *f, B1 a1, B2 a2) {
    return new functorn_2<RET, A1, A2>(f, a1, a2);
}

// 0 arguments base event - 3 extra arguments
template <typename RET, typename A1, typename B1, typename A2, typename B2, typename A3, typename B3>
inline functor_base<RET> *bind(functor_base<RET, A1, A2, A3> *f, B1 a1, B2 a2, B3 a3) {
    return new functorn_3<RET, A1, A2, A3>(f, a1, a2, a3);
}

// 1 arguments base event - 1 extra argument
template <typename RET, typename BE1, typename A1, typename B1>
inline functor_base<RET, BE1> *bind(functor_base<RET, BE1, A1> *f, B1 a1) {
    return new functorn_1<RET, A1, BE1>(f, a1);
}

// 1 arguments base event - 2 extra argument
template <typename RET, typename BE1, typename A1, typename B1, typename A2, typename B2>
inline functor_base<RET, BE1> *bind(functor_base<RET, BE1, A1, A2> *f, B1 a1, B2 a2) {
    return new functorn_2<RET, A1, A2, BE1>(f, a1, a2);
}

// 1 arguments base event - 3 extra argument
template <typename RET, typename BE1, typename A1, typename B1, typename A2, typename B2, typename A3, typename B3>
inline functor_base<RET, BE1> *bind(functor_base<RET, BE1, A1, A2, A3> *f, B1 a1, B2 a2, B3 a3) {
    return new functorn_3<RET, A1, A2, A3, BE1>(f, a1, a2, a3);
}

// 2 arguments base event - 1 extra argument
template <typename RET, typename BE1, typename BE2, typename A1, typename B1>
inline functor_base<RET, BE1, BE2> *bind(functor_base<RET, BE1, BE2, A1> *f, B1 a1) {
    return new functorn_1<RET, A1, BE1, BE2>(f, a1);
}

// 2 arguments base event - 2 extra argument
template <typename RET, typename BE1, typename BE2, typename A1, typename B1, typename A2, typename B2>
inline functor_base<RET, BE1, BE2> *bind(functor_base<RET, BE1, BE2, A1, A2> *f, B1 a1, B2 a2) {
    return new functorn_2<RET, A1, A2, BE1, BE2>(f, a1, a2);
}

// 2 arguments base event - 3 extra argument
template <typename RET, typename BE1, typename BE2, typename A1, typename B1, typename A2, typename B2, typename A3,
          typename B3>
inline functor_base<RET, BE1, BE2> *bind(functor_base<RET, BE1, BE2, A1, A2, A3> *f, B1 a1, B2 a2, B3 a3) {
    return new functorn_3<RET, A1, A2, A3, BE1, BE2>(f, a1, a2, a3);
}

// 3 arguments base event - 1 extra argument
template <typename RET, typename BE1, typename BE2, typename BE3, typename A1, typename B1>
inline functor_base<RET, BE1, BE2, BE3> *bind(functor_base<RET, BE1, BE2, BE3, A1> *f, B1 a1) {
    return new functorn_1<RET, A1, BE1, BE2, BE3>(f, a1);
}

// 3 arguments base event - 2 extra argument
template <typename RET, typename BE1, typename BE2, typename BE3, typename A1, typename B1, typename A2, typename B2>
inline functor_base<RET, BE1, BE2, BE3> *bind(functor_base<RET, BE1, BE2, BE3, A1, A2> *f, B1 a1, B2 a2) {
    return new functorn_2<RET, A1, A2, BE1, BE2, BE3>(f, a1, a2);
}

// 3 arguments base event - 3 extra argument
template <typename RET, typename BE1, typename BE2, typename BE3, typename A1, typename B1, typename A2, typename B2,
          typename A3, typename B3>
inline functor_base<RET, BE1, BE2, BE3> *bind(functor_base<RET, BE1, BE2, BE3, A1, A2, A3> *f, B1 a1, B2 a2, B3 a3) {
    return new functorn_3<RET, A1, A2, A3, BE1, BE2, BE3>(f, a1, a2, a3);
}

// 4 arguments base event - 1 extra argument
template <typename RET, typename BE1, typename BE2, typename BE3, typename BE4, typename A1, typename B1>
inline functor_base<RET, BE1, BE2, BE3, BE4> *bind(functor_base<RET, BE1, BE2, BE3, BE4, A1> *f, B1 a1) {
    return new functorn_1<RET, A1, BE1, BE2, BE3, BE4>(f, a1);
}

// 4 arguments base event - 2 extra argument
template <typename RET, typename BE1, typename BE2, typename BE3, typename BE4, typename A1, typename B1, typename A2,
          typename B2>
inline functor_base<RET, BE1, BE2, BE3, BE4> *bind(functor_base<RET, BE1, BE2, BE3, BE4, A1, A2> *f, B1 a1, B2 a2) {
    return new functorn_2<RET, A1, A2, BE1, BE2, BE3, BE4>(f, a1, a2);
}

// 4 arguments base event - 3 extra argument
template <typename RET, typename BE1, typename BE2, typename BE3, typename BE4, typename A1, typename B1, typename A2,
          typename B2, typename A3, typename B3>
inline functor_base<RET, BE1, BE2, BE3, BE4> *bind(functor_base<RET, BE1, BE2, BE3, BE4, A1, A2, A3> *f, B1 a1, B2 a2,
                                                   B3 a3) {
    return new functorn_3<RET, A1, A2, A3, BE1, BE2, BE3, BE4>(f, a1, a2, a3);
}
}
#endif
