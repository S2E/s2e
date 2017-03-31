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

unsigned m_activeSignals;
unsigned m_size;

private:
func_t *m_funcs;

public:
SIGNAL_CLASS() {
    m_size = 0;
    m_funcs = 0;
    m_activeSignals = 0;
}

SIGNAL_CLASS(const SIGNAL_CLASS &one) {
    m_activeSignals = one.m_activeSignals;
    m_size = one.m_size;
    m_funcs = new func_t[m_size];
    for (unsigned i = 0; i < m_size; ++i) {
        m_funcs[i] = one.m_funcs[i];
        m_funcs[i]->incref();
    }
}

virtual ~SIGNAL_CLASS() {
    disconnectAll();
    if (m_funcs) {
        delete[] m_funcs;
    }
}

void disconnectAll() {
    for (unsigned i = 0; i < m_size; ++i) {
        if (m_funcs[i] && !m_funcs[i]->decref()) {
            delete m_funcs[i];
        }
        m_funcs[i] = NULL;
    }
}

virtual void disconnect(void *functor) {
    assert(m_activeSignals > 0);

    for (unsigned i = 0; i < m_size; ++i) {
        if (m_funcs[i] == functor) {
            if (!m_funcs[i]->decref()) {
                delete m_funcs[i];
            }
            --m_activeSignals;
            m_funcs[i] = NULL;
            break;
        }
    }
}

connection connect_front(func_t fcn) {
    if (!m_size) {
        return connect(fcn);
    }

    fcn->incref();
    ++m_activeSignals;

    ++m_size;
    func_t *nf = new func_t[m_size];

    memcpy(nf + 1, m_funcs, sizeof(func_t) * (m_size - 1));
    delete[] m_funcs;
    m_funcs = nf;
    m_funcs[0] = fcn;
    return connection(this, fcn);
}

connection connect(func_t fcn) {
    fcn->incref();
    ++m_activeSignals;
    for (unsigned i = 0; i < m_size; ++i) {
        if (!m_funcs[i]) {
            m_funcs[i] = fcn;
            return connection(this, fcn);
        }
    }
    ++m_size;
    func_t *nf = new func_t[m_size];

    if (m_funcs) {
        memcpy(nf, m_funcs, sizeof(func_t) * (m_size - 1));
        delete[] m_funcs;
    }
    m_funcs = nf;

    m_funcs[m_size - 1] = fcn;
    return connection(this, fcn);
}

bool empty() const {
    return m_activeSignals == 0;
}

void emit(OPERATOR_PARAM_DECL) {
    for (unsigned i = 0; i < m_size; ++i) {
        if (m_funcs[i]) {
            m_funcs[i]->operator()(CALL_PARAMS);
        }
    }
}

// This is intended for optimization purposes only.
// The softmmu code needs to check whether there are signals registered
// for memory tracing. To avoid going through several layers of code,
// this function returns a pointer to the internal field.
unsigned *getActiveSignalsPtr() {
    return &m_activeSignals;
}

#undef SIGNAL_CLASS
#undef FUNCTOR_NAME
#undef TYPENAMES
#undef BASE_CLASS_INST
#undef FUNCT_DECL
#undef OPERATOR_PARAM_DECL
#undef CALL_PARAMS
