#include <cstdlib>
#include <cstdint>
#include <map>
#include <iostream>
#include <sstream>
#include <cctype>
#include <fcntl.h>
#include <unistd.h>
extern "C" {
#include "kallsyms.h"
}

typedef std::map<uint64_t, std::string> SymTab;

static void emit(uint64_t addr, const SymTab& st, std::stringstream &ss)
{
    static const uint64_t limit = 1UL * 1024 * 1024;
    auto i = st.upper_bound(addr);
    if (i == st.begin() || addr - (--i)->first > limit) {
        ss << "0x" << std::hex << addr << " ";
    } else {
        ss << i->second << "+0x" << std::hex << addr - i->first << " ";
    }
}

int main(int argc, char** argv)
{
    SymTab symtab;
    kallsyms__parse(argv[1], &symtab, [](void* s,const char *name,
                                         char type, u64 start) {
        SymTab *st = (SymTab*)s;
        st->emplace(start, name);
        return 0;
    });
    std::string line;
    while(std::cin >> line) {
        line += '-';
        static const char prefix[] = "GUEST";
        size_t pos = sizeof(prefix) - 1;
        bool dir = false;
        std::stringstream ss;
        if(strncmp(line.c_str(), prefix, pos)) {
            write(1, "\n", 1);
            continue;
        }
        uint64_t prev = 0;
        uint64_t addr = 0;
        for(auto end = line.size(); pos != end; ++pos) {
            auto c = line[pos];
            switch (c) {
                case '+':
                case '-':
                    emit(dir ? prev -= addr : prev += addr, symtab, ss);
                    addr = 0;
            }
            switch (c) {
                case '+':
                case '_':
                    dir = false;
                    break;
                case '-':
                    dir = true;
                    break;
                default: {
                    if (!isxdigit(c))
                        break;
                    addr *= 16;
                    addr += c >= 'a' ? c - 'a' + 10 : c >= 'A' ? c - 'A' + 10 : c - '0';
                }
            }
        }
        ss << '\n';
        auto str = ss.str();
        write(1, str.c_str(), str.size());
    }
}