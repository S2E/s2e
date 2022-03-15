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

#include <fsigc++/fsigc++.h>
#include <iostream>

class MyPlugin {
public:
    fsigc::signal<void> sig0;
    fsigc::signal<void, int> sig1;
    fsigc::signal<void, int, void *> sig2;
};

class MyPlugin1 {
public:
    uint64_t m_counter;
    static uint64_t s_counter;

    sigc::connection m_fc0, m_fc1, m_fc2;

    ~MyPlugin1() {
        m_fc1.disconnect();
        m_fc2.disconnect();
    }

    void init(MyPlugin *plg) {
        m_counter = 0;
        m_fc0 = plg->sig0.connect(fsigc::mem_fun(*this, &MyPlugin1::myEvent0));
        m_fc1 = plg->sig1.connect(fsigc::mem_fun(*this, &MyPlugin1::myEvent1));
        m_fc2 = plg->sig2.connect(fsigc::mem_fun(*this, &MyPlugin1::myEvent2));

        // Bind static parameters
        plg->sig0.connect(fsigc::ptr_fun(&MyPlugin1::mySEvent0));
        plg->sig1.connect(fsigc::bind(fsigc::ptr_fun(&MyPlugin1::mySEvent2), (void *) 0x111111));
        plg->sig1.connect(fsigc::bind(fsigc::ptr_fun(&MyPlugin1::mySEvent3), (void *) 0x111111, 123));

        plg->sig2.connect(fsigc::bind(fsigc::ptr_fun(&MyPlugin1::mySEvent3), 123));
        plg->sig2.connect(fsigc::bind(fsigc::ptr_fun(&MyPlugin1::mySEvent3), 123));
        plg->sig2.connect(fsigc::bind(fsigc::ptr_fun(&MyPlugin1::mySEvent4), 123, false));

        plg->sig0.connect(fsigc::bind(fsigc::mem_fun(*this, &MyPlugin1::myEvent1), 0xdeadbeef));
    }

private:
    void myEventA(void *p1, unsigned p2, bool p3, int p4) {
        ++m_counter;
    }

    void myEvent0() {
        // std::cout << "myEvent1 " << p1 << " " << m_counter << std::endl;
        ++m_counter;
    }

    void myEvent1(int p1) {
        std::cout << "myEvent1 " << std::hex << p1 << " " << m_counter << std::endl;
        ++m_counter;
    }
    void myEvent2(int p1, void *p2) {
        std::cout << "myEvent2 " << std::hex << p1 << " " << p2 << " " << m_counter << std::endl;
        ++m_counter;
    }

    /*******/

    static void mySEvent0() {
        std::cout << "mySEvent0 " << s_counter << std::endl;
        ++s_counter;
    }

    static void mySEvent1(int p1) {
        std::cout << "mySEvent1 " << std::hex << p1 << " " << s_counter << std::endl;
        ++s_counter;
    }
    static void mySEvent2(int p1, void *p2) {
        std::cout << "mySEvent2 " << std::hex << p1 << " " << p2 << " " << s_counter << std::endl;
        ++s_counter;
    }
    static void mySEvent3(int p1, void *p2, unsigned bla) {
        std::cout << "mySEvent2 " << std::hex << p1 << " " << p2 << " " << bla << s_counter << std::endl;
        ++s_counter;
    }
    static void mySEvent4(int p1, void *p2, unsigned bla, bool bla2) {
        std::cout << "mySEvent2 " << std::hex << p1 << " " << p2 << " " << bla << s_counter << std::endl;
        ++s_counter;
    }
};

uint64_t MyPlugin1::s_counter = 0;

int main(int argc, char **argv) {
    MyPlugin p0;
    MyPlugin1 p1;
    p1.init(&p0);

    if (argc == 1) {
        std::cout << "Testing fast signals" << std::endl;
        for (unsigned i = 0; i < 100000000; ++i) {
            p0.sig0.emit();
            p0.sig1.emit(i);
            p0.sig2.emit(i, (char *) (uintptr_t) (i + 1));
        }
    }

    std::cout << p1.m_counter << std::endl;
}
