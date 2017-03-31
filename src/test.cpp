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

#include <iostream>
#include <sigc++/sigc++.h>
#include "signals.h"

class MyPlugin {
public:
    fsigc::signal<void> sig0;
    fsigc::signal<void, int> sig1;
    fsigc::signal<void, int, int> sig2;
    fsigc::signal<void, int, int, int> sig3;
    fsigc::signal<void, int, int, int, int> sig4;
    fsigc::signal<void, int, int, int, int, int> sig5;
    fsigc::signal<void, int, int, int, int, int, int> sig6;
    fsigc::signal<void, int, int, int, int, int, int, int> sig7;

    sigc::signal<void> nat_sig0;
    sigc::signal<void, int> nat_sig1;
    sigc::signal<void, int, int> nat_sig2;
    sigc::signal<void, int, int, int> nat_sig3;
    sigc::signal<void, int, int, int, int> nat_sig4;
    sigc::signal<void, int, int, int, int, int> nat_sig5;
    sigc::signal<void, int, int, int, int, int, int> nat_sig6;
    sigc::signal<void, int, int, int, int, int, int, int> nat_sig7;
};

class MyPlugin1 {

    fsigc::connection m_fc0, m_fc1, m_fc2, m_fc3, m_fc4, m_fc5, m_fc6, m_fc7;
    sigc::connection m_nc0, m_nc1, m_nc2, m_nc3, m_nc4, m_nc5, m_nc6, m_nc7;

public:
    uint64_t m_counter;
    static uint64_t s_counter;

    ~MyPlugin1() {
        m_fc1.disconnect();
        m_fc2.disconnect();

        m_nc1.disconnect();
        m_nc2.disconnect();
    }

    void init(MyPlugin *plg) {
        m_counter = 0;
        m_fc0 = plg->sig0.connect(fsigc::mem_fun(*this, &MyPlugin1::myEvent0));
        m_fc1 = plg->sig1.connect(fsigc::mem_fun(*this, &MyPlugin1::myEvent1));
        m_fc2 = plg->sig2.connect(fsigc::mem_fun(*this, &MyPlugin1::myEvent2));
        m_fc3 = plg->sig3.connect(fsigc::mem_fun(*this, &MyPlugin1::myEvent3));
        m_fc4 = plg->sig4.connect(fsigc::mem_fun(*this, &MyPlugin1::myEvent4));
        m_fc5 = plg->sig5.connect(fsigc::mem_fun(*this, &MyPlugin1::myEvent5));
        m_fc6 = plg->sig6.connect(fsigc::mem_fun(*this, &MyPlugin1::myEvent6));
        m_fc7 = plg->sig7.connect(fsigc::mem_fun(*this, &MyPlugin1::myEvent7));

        // Bind extra parameters
        plg->sig0.connect(fsigc::bind(fsigc::mem_fun(*this, &MyPlugin1::myEvent1), 0xdeadbeef));
        plg->sig1.connect(fsigc::bind(fsigc::mem_fun(*this, &MyPlugin1::myEvent2), 0xbadcafe));
        plg->sig1.connect(fsigc::bind(fsigc::mem_fun(*this, &MyPlugin1::myEvent3), 0xbadcafe, 0xdeadbeef));

        plg->sig2.connect(fsigc::bind(fsigc::mem_fun(*this, &MyPlugin1::myEvent3), 0xbadcafe));
        plg->sig2.connect(fsigc::bind(fsigc::mem_fun(*this, &MyPlugin1::myEvent4), 0xbadcafe, 0xdeadbeef));

        plg->sig3.connect(fsigc::bind(fsigc::mem_fun(*this, &MyPlugin1::myEvent4), 0xbadcafe));
        plg->sig3.connect(fsigc::bind(fsigc::mem_fun(*this, &MyPlugin1::myEvent5), 0xbadcafe, 0xdeadbeef));

        plg->sig4.connect(fsigc::bind(fsigc::mem_fun(*this, &MyPlugin1::myEvent5), 0xbadcafe));
        plg->sig4.connect(fsigc::bind(fsigc::mem_fun(*this, &MyPlugin1::myEvent6), 0xbadcafe, 0xdeadbeef));

        // Bind static parameters
        plg->sig0.connect(fsigc::ptr_fun(&MyPlugin1::mySEvent0));
        plg->sig2.connect(fsigc::bind(fsigc::ptr_fun(&MyPlugin1::mySEvent3), 0x111111));

        m_nc0 = plg->nat_sig0.connect(sigc::mem_fun(*this, &MyPlugin1::myEvent0));
        m_nc1 = plg->nat_sig1.connect(sigc::mem_fun(*this, &MyPlugin1::myEvent1));
        m_nc2 = plg->nat_sig2.connect(sigc::mem_fun(*this, &MyPlugin1::myEvent2));
        m_nc3 = plg->nat_sig3.connect(sigc::mem_fun(*this, &MyPlugin1::myEvent3));
        m_nc4 = plg->nat_sig4.connect(sigc::mem_fun(*this, &MyPlugin1::myEvent4));
        m_nc5 = plg->nat_sig5.connect(sigc::mem_fun(*this, &MyPlugin1::myEvent5));
        m_nc6 = plg->nat_sig6.connect(sigc::mem_fun(*this, &MyPlugin1::myEvent6));
        m_nc7 = plg->nat_sig7.connect(sigc::mem_fun(*this, &MyPlugin1::myEvent7));

        plg->nat_sig0.connect(sigc::bind(sigc::mem_fun(*this, &MyPlugin1::myEvent1), 0xdeadbeef));
    }

private:
    void myEvent0() {
        // std::cout << "myEvent1 " << p1 << " " << m_counter << std::endl;
        ++m_counter;
    }

    void myEvent1(int p1) {
        std::cout << "myEvent1 " << std::hex << p1 << " " << m_counter << std::endl;
        ++m_counter;
    }
    void myEvent2(int p1, int p2) {
        std::cout << "myEvent2 " << std::hex << p1 << " " << p2 << " " << m_counter << std::endl;
        ++m_counter;
    }
    void myEvent3(int p1, int p2, int p3) {
        std::cout << "myEvent3 " << std::hex << p1 << " " << p2 << " " << p3 << std::endl;
        ++m_counter;
    }
    void myEvent4(int p1, int p2, int p3, int p4) {
        // std::cout << "myEvent1 " << p1 << " " << m_counter << std::endl;
        ++m_counter;
    }
    void myEvent5(int p1, int p2, int p3, int p4, int p5) {
        // std::cout << "myEvent1 " << p1 << " " << m_counter << std::endl;
        ++m_counter;
    }
    void myEvent6(int p1, int p2, int p3, int p4, int p5, int p6) {
        // std::cout << "myEvent1 " << p1 << " " << m_counter << std::endl;
        ++m_counter;
    }
    void myEvent7(int p1, int p2, int p3, int p4, int p5, int p6, int p7) {
        // std::cout << "myEvent1 " << p1 << " " << m_counter << std::endl;
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
    static void mySEvent2(int p1, int p2) {
        std::cout << "mySEvent2 " << std::hex << p1 << " " << p2 << " " << s_counter << std::endl;
        ++s_counter;
    }
    static void mySEvent3(int p1, int p2, int p3) {
        std::cout << "mySEvent3 " << std::hex << p1 << " " << p2 << " " << p3 << std::endl;
        ++s_counter;
    }
    static void mySEvent4(int p1, int p2, int p3, int p4) {
        // std::cout << "myEvent1 " << p1 << " " << m_counter << std::endl;
        ++s_counter;
    }
    static void mySEvent5(int p1, int p2, int p3, int p4, int p5) {
        // std::cout << "myEvent1 " << p1 << " " << m_counter << std::endl;
        ++s_counter;
    }
    static void mySEvent6(int p1, int p2, int p3, int p4, int p5, int p6) {
        // std::cout << "myEvent1 " << p1 << " " << m_counter << std::endl;
        ++s_counter;
    }
    static void mySEvent7(int p1, int p2, int p3, int p4, int p5, int p6, int p7) {
        // std::cout << "myEvent1 " << p1 << " " << m_counter << std::endl;
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
            p0.sig2.emit(i, i + 1);
            p0.sig3.emit(i, i + 1, i + 2);
            p0.sig4.emit(i, i + 1, i + 2, i + 3);
            p0.sig5.emit(i, i + 1, i + 2, i + 3, i + 4);
            p0.sig6.emit(i, i + 1, i + 2, i + 3, i + 4, i + 5);
            p0.sig7.emit(i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6);
        }
    } else {
        std::cout << "Testing slow signals" << std::endl;
        for (unsigned i = 0; i < 100000000; ++i) {
            p0.nat_sig0.emit();
            p0.nat_sig1.emit(i);
            p0.nat_sig2.emit(i, i + 1);
            p0.nat_sig3.emit(i, i + 1, i + 2);
            p0.nat_sig4.emit(i, i + 1, i + 2, i + 3);
            p0.nat_sig5.emit(i, i + 1, i + 2, i + 3, i + 4);
            p0.nat_sig6.emit(i, i + 1, i + 2, i + 3, i + 4, i + 5);
            p0.nat_sig7.emit(i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6);
        }
    }

    std::cout << p1.m_counter << std::endl;
}
