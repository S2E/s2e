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

template <class T, typename RET, TYPENAMES> class FUNCTOR_NAME : public functor_base<RET, BASE_CLASS_INST> {
public:
    typedef RET (T::*func_t)(FUNCT_DECL);

protected:
    func_t m_func;
    T *m_obj;

public:
    FUNCTOR_NAME(T *obj, func_t f) {
        m_obj = obj;
        m_func = f;
    };

    virtual ~FUNCTOR_NAME() {
    }

    virtual RET operator()(OPERATOR_PARAM_DECL) {
        FASSERT(this->m_refcount > 0);
        return (*m_obj.*m_func)(CALL_PARAMS);
    };
};

template <class T, typename RET, TYPENAMES>
inline functor_base<RET, BASE_CLASS_INST> *mem_fun(T &obj, RET (T::*f)(FUNCT_DECL)) {
    return new FUNCTOR_NAME<T, RET, FUNCT_DECL>(&obj, f);
}

/*** Stateless functors ***/
#define fsigcxglue(x, y) x##y
#define fsigcglue(x, y) fsigcxglue(x, y)

template <typename RET, TYPENAMES> class fsigcglue(FUNCTOR_NAME, _sl) : public functor_base<RET, BASE_CLASS_INST> {
public:
    typedef RET (*func_t)(FUNCT_DECL);

protected:
    func_t m_func;

public:
    fsigcglue(FUNCTOR_NAME, _sl)(func_t f) {
        m_func = f;
    };

    virtual ~fsigcglue(FUNCTOR_NAME, _sl)() {
    }

    virtual RET operator()(OPERATOR_PARAM_DECL) {
        FASSERT(this->m_refcount > 0);
        return (*m_func)(CALL_PARAMS);
    };
};

template <typename RET, TYPENAMES> inline functor_base<RET, BASE_CLASS_INST> *ptr_fun(RET (*f)(FUNCT_DECL)) {
    return new fsigcglue(FUNCTOR_NAME, _sl)<RET, FUNCT_DECL>(f);
}

#undef fsigcglue
#undef fsigcxglue
