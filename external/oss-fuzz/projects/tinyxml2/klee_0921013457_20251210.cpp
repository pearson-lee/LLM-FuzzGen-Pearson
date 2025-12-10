// klee_harness_tinyxml2.cpp
#include "tinyxml2.h"
#include <klee/klee.h>
#include <cstring>

int main() {
    const unsigned MAX = 64; // 限制長度以避免路徑爆炸
    char buf[MAX+1];
    // 讓 KLEE 對 buf[0..N-1] 做符號化，並將 N 也符號化但受限
    unsigned N;
    klee_make_symbolic(&N, sizeof(N), "N");
    klee_assume(N > 0);
    klee_assume(N <= MAX);

    klee_make_symbolic(buf, N, "buf");
    buf[N] = '\0';

    // 限制字元集合：只允許一小集合以減少分支
    for (unsigned i = 0; i < N; ++i) {
        // allowed: '<', '>', '/', letters, digits, space, newline
        klee_assume(
            buf[i] == '<' ||
            buf[i] == '>' ||
            buf[i] == '/' ||
            (buf[i] >= 'a' && buf[i] <= 'z') ||
            (buf[i] >= 'A' && buf[i] <= 'Z') ||
            (buf[i] >= '0' && buf[i] <= '9') ||
            buf[i] == ' ' || buf[i] == '\n' || buf[i] == '\t'
        );
    }

    tinyxml2::XMLDocument doc;
    doc.Parse(buf);

    // 簡單 visitor，和你 fuzz target 的 visitor 行為類似
    class V: public tinyxml2::XMLVisitor {
    public:
        bool VisitEnter(const tinyxml2::XMLDocument&) override { return true; }
        bool VisitExit(const tinyxml2::XMLDocument&) override { return true; }
    } visitor;

    doc.Accept(&visitor);
    return 0;
}
