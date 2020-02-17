///
/// Copyright (C) 2013-2014, Dependable Systems Laboratory, EPFL
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
///

#ifndef S2E_PLUGINS_CALLTREE_H
#define S2E_PLUGINS_CALLTREE_H

#include <algorithm>
#include <map>
#include <set>
#include <string>

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_ostream.h>

#include <s2e/Utils.h>

namespace s2e {
namespace plugins {

namespace calltree {

template <typename T> class CallTree;
template <typename T> class FunctionCall;

template <typename T> class CallTreeVisitor {
public:
    virtual ~CallTreeVisitor() {
    }
    virtual void visit(const CallTree<T> &tree) = 0;
    virtual void visit(const FunctionCall<T> &call) = 0;
};

struct CallStackEntry {
    std::string Module;
    std::string FunctionName;
    uint64_t ReturnAddress;
    uint64_t FunctionAddress;
};

typedef std::vector<CallStackEntry> CallStack;
typedef std::vector<CallStack> CallStacks;
typedef std::pair<std::string, uint64_t> Location;

template <typename T> class FunctionCall {
public:
    typedef std::set<T> Things;
    typedef std::map<Location, Things> ThingsAtLocation;
    /* One call site can lead to different functions */
    typedef std::multimap<uint64_t, FunctionCall *> CallSites;

private:
    FunctionCall *m_parent;
    std::string m_module;
    uint64_t m_function;
    std::string m_functionName;
    CallSites m_callSites;
    ThingsAtLocation m_things;

    /* How many things we have in this subtree */
    int m_thingsCount;

    /* How many times did we pick an object from that function? */
    unsigned m_selectionCount;

private:
    void updateThingsCount(int increment) {
        if (!increment) {
            return;
        }

        for (FunctionCall *fc = this; fc; fc = fc->m_parent) {
            fc->m_thingsCount += increment;
        }
    }

public:
    typedef typename CallSites::iterator iterator;

    const std::string &getModule() const {
        return m_module;
    }

    void accept(CallTreeVisitor<T> *visitor) const {
        visitor->visit(*this);
    }

    uint64_t getFunction() const {
        return m_function;
    }

    const std::string &getFunctionName() const {
        return m_functionName;
    }

    const CallSites &getCallSites() const {
        return m_callSites;
    }

    void getNonEmptyCallSites(CallSites &cs) const {
        foreach2 (it, m_callSites.begin(), m_callSites.end()) {
            FunctionCall *fc = (*it).second;
            if (fc->getThingsCount() > 0) {
                cs.insert(*it);
            }
        }
    }

    const ThingsAtLocation &getThings() const {
        return m_things;
    }

    iterator begin() {
        return m_callSites.begin();
    }
    iterator end() {
        return m_callSites.end();
    }

    FunctionCall(FunctionCall *parent, const std::string &module, uint64_t function, const std::string &functionName)
        : m_parent(parent), m_module(module), m_function(function), m_functionName(functionName), m_thingsCount(0),
          m_selectionCount(0) {
    }

    ~FunctionCall() {
        foreach2 (it, m_callSites.begin(), m_callSites.end()) { delete (*it).second; }
        updateThingsCount(-m_thingsCount);
        assert(m_thingsCount == 0);
    }

    FunctionCall *get(const CallStackEntry &ce) {
        typename CallSites::iterator it = m_callSites.find(ce.ReturnAddress);
        if (it == m_callSites.end()) {
            return nullptr;
        }

        while (it != m_callSites.end() && (*it).first == ce.ReturnAddress) {
            const FunctionCall *fc = (*it).second;
            if (fc->m_module == ce.Module && fc->m_function == ce.FunctionAddress) {
                return (*it).second;
            }
            ++it;
        }

        return nullptr;
    }

    void add(uint64_t callSite, FunctionCall *call) {
        m_callSites.insert(std::make_pair(callSite, call));
    }

    void add(T t, const Location &loc) {
        m_things[loc].insert(t);
        updateThingsCount(1);
    }

    void remove(FunctionCall *call) {
        foreach2 (it, m_callSites.begin(), m_callSites.end()) {
            if ((*it).second == call) {
                m_callSites.erase((*it).first);
                // m_thingsCount -= call->m_thingsCount;
                // assert(m_thingsCount >= 0);
                assert(call->m_thingsCount == 0);
                delete call;
                break;
            }
        }

        if (!(m_things.size() == 0 && m_callSites.size() == 0)) {
            return;
        }

        if (m_parent) {
            m_parent->remove(this);
        }
    }

    void remove(T t, bool removeParents) {
        llvm::SmallVector<Location, 5> pcToErase;
        foreach2 (it, m_things.begin(), m_things.end()) {
            Things &things = (*it).second;
            int erased = things.erase(t);
            updateThingsCount(-erased);
            if (things.size() == 0) {
                pcToErase.push_back((*it).first);
            }
        }

        foreach2 (it, pcToErase.begin(), pcToErase.end()) { m_things.erase(*it); }

        if (removeParents) {
            remove(this);
        }
    }

    int getThingsCount() const {
        return m_thingsCount;
    }

    unsigned getSelectionCount() const {
        return m_selectionCount;
    }

    void updateSelectionCount(int increment) {
        if (!increment) {
            return;
        }

        for (FunctionCall *fc = this; fc; fc = fc->m_parent) {
            fc->m_selectionCount += increment;
        }
    }
};

template <typename T> class CallTree {
public:
    CallTree() {
        m_root = new FunctionCall<T>(nullptr, "system", 0, "<unknownfunc>");
        m_removeEmptyCallStacks = false;
    }

    ~CallTree() {
        delete m_root;
    }

    void accept(CallTreeVisitor<T> *visitor) const {
        visitor->visit(*this);
    }

    const FunctionCall<T> *getRoot() const {
        return m_root;
    }

    void setRemoveEmptyCallStacks() {
        m_removeEmptyCallStacks = true;
    }

private:
    typedef llvm::DenseMap<T, FunctionCall<T> *> ThingLocation;

    FunctionCall<T> *m_root;
    ThingLocation m_thingsLocation;
    bool m_removeEmptyCallStacks;

public:
    bool add(T thing, const CallStack &cs, const Location &loc) {
        if (m_thingsLocation.find(thing) != m_thingsLocation.end()) {
            return false;
        }

        FunctionCall<T> *current = m_root;
        foreach2 (it, cs.begin(), cs.end()) {
            const CallStackEntry &ce = *it;
            FunctionCall<T> *child = nullptr;

            child = current->get(ce);
            if (!child) {
                child = new FunctionCall<T>(current, ce.Module, ce.FunctionAddress, ce.FunctionName);
                current->add(ce.ReturnAddress, child);
            }

            current = child;
        }
        current->add(thing, loc);
        m_thingsLocation[thing] = current;

        return true;
    }

    void remove(T thing) {
        typename ThingLocation::iterator it = m_thingsLocation.find(thing);
        if (it == m_thingsLocation.end()) {
            return;
        }
        (*it).second->remove(thing, m_removeEmptyCallStacks);
        m_thingsLocation.erase(it);
    }

    bool select(T thing) {
        typename ThingLocation::iterator it = m_thingsLocation.find(thing);
        if (it == m_thingsLocation.end()) {
            return false;
        }
        (*it).second->updateSelectionCount(1);
        return true;
    }

    unsigned size() const {
        int ret = m_root->getThingsCount();
        assert(ret >= 0);
        assert((unsigned) ret == m_thingsLocation.size());
        return (unsigned) ret;
    }
};

/**
 * Selects a leaf by randomly walking the call tree
 * from the root.
 */
template <typename T> class CallTreeRandomPath : public CallTreeVisitor<T> {
public:
    typedef typename FunctionCall<T>::Things ThingsT;

private:
    ThingsT m_things;

public:
    CallTreeRandomPath(){};

    void visit(const CallTree<T> &tree) {
        tree.getRoot()->accept(this);
    }

    void visit(const FunctionCall<T> &call) {
        typename FunctionCall<T>::CallSites cs;
        call.getNonEmptyCallSites(cs);
        const typename FunctionCall<T>::ThingsAtLocation &t = call.getThings();

        unsigned count = cs.size() + std::min<unsigned>(t.size(), 1);

        if (!count) {
            return;
        }

        unsigned rndIndex = rand() % count;
        unsigned i = 0;

        if (rndIndex >= cs.size()) {
            rndIndex = rand() % t.size();
            // Pick one thing
            foreach2 (it, t.begin(), t.end()) {
                if (i == rndIndex) {
                    m_things = (*it).second;
                    break;
                }
                ++i;
            }
        } else {
            foreach2 (it, cs.begin(), cs.end()) {
                if (i == rndIndex) {
                    (*it).second->accept(this);
                    break;
                }
                ++i;
            }
        }
    }

    const ThingsT &getSelectedThings() const {
        return m_things;
    }
};

/**
 * Prints the call tree in graphviz format
 */
template <typename T> class CallTreeDotPrinter : public CallTreeVisitor<T> {
private:
    typedef typename FunctionCall<T>::Things ThingsT;

    llvm::raw_ostream &m_os;
    unsigned m_totalSelectionCount;

public:
    CallTreeDotPrinter(llvm::raw_ostream &os) : m_os(os), m_totalSelectionCount(0) {
    }

    void visit(const CallTree<T> &tree) {
        m_totalSelectionCount = tree.getRoot()->getSelectionCount();

        m_os << "digraph G {\n";
        m_os << "rankdir=\"LR\";\n";
        tree.getRoot()->accept(this);
        m_os << "}\n";
    }

    void visit(const FunctionCall<T> &call) {
        std::string nodeColor = "color = \"#000000\"";
        std::string fontColor = "fontcolor = \"#000000\"";

        if (call.getThingsCount() == 0) {
            nodeColor = "color = \"#c0c0c0\"";
            fontColor = "fontcolor = \"#c0c0c0\"";
        }

        m_os << '_' << &call << " [label=\"" << call.getModule() << ":" << hexval(call.getFunction()) << "\\n";

        if (call.getFunctionName().size() > 0) {
            m_os << "(" << call.getFunctionName() << ")\\n";
        }

        m_os << "Active#: " << call.getThingsCount() << "\\n";
        m_os << "Selection#: " << call.getSelectionCount();
        if (m_totalSelectionCount) {
            m_os << " (" << call.getSelectionCount() * 100 / m_totalSelectionCount << " %)";
        }

        m_os << "\", "
             << "shape=box, " << nodeColor << "," << fontColor << ","
             << "];\n";

        foreach2 (it, call.getThings().begin(), call.getThings().end()) {
            const Location &location = (*it).first;
            const ThingsT &things = (*it).second;
            m_os << '_' << &call << '_' << location.second << " [label=\"" << location.first << "\\n"
                 << hexval(location.second) << ": " << things.size() << " objects"
                 << "\""
                 << "];\n";

            m_os << '_' << &call << "->" << '_' << &call << '_' << location.second << ";\n";
        }

        foreach2 (it, call.getCallSites().begin(), call.getCallSites().end()) {
            (*it).second->accept(this);
            uint64_t callsite = (*it).first;
            m_os << '_' << &call << "->" << '_' << (*it).second << "[label=\"" << hexval(callsite) << "\", "
                 << nodeColor << "," << fontColor << "];\n";
        }
    }
};

/**
 * Prints the call tree in text format
 */
template <typename T> class CallTreeTextPrinter : public CallTreeVisitor<T> {
private:
    typedef typename FunctionCall<T>::Things ThingsT;

    llvm::raw_ostream &m_out;
    unsigned m_nesting;

    void ident(unsigned i) {
        while (i-- > 0) {
            m_out << ' ';
        }
    }

public:
    CallTreeTextPrinter(llvm::raw_ostream &out) : m_out(out), m_nesting(0) {
    }

    void visit(const CallTree<T> &tree) {
        m_out << "CALL TREE\n";
        ++m_nesting;
        tree.getRoot()->accept(this);
        --m_nesting;
    }

    void visit(const FunctionCall<T> &call) {
        ident(m_nesting);
        m_out << "Function: " << call.getModule() << ":" << hexval(call.getFunction()) << "\n";
        foreach2 (it, call.getThings().begin(), call.getThings().end()) {
            const ThingsT &things = (*it).second;
            ident(m_nesting);
            m_out << "Thing: " << hexval((*it).first.second) << " " << things.size() << "\n";
        }

        foreach2 (it, call.getCallSites().begin(), call.getCallSites().end()) {
            ident(m_nesting);
            m_out << "Call site " << hexval((*it).first) << "\n";

            ++m_nesting;
            (*it).second->accept(this);
            --m_nesting;

            m_out << "\n";
        }
    }
};
} // namespace calltree
} // namespace plugins
} // namespace s2e

#endif
