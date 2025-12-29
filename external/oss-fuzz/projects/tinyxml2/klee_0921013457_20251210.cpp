#include "tinyxml2.h"
#include <klee/klee.h>
#include <assert.h>
#include <cstddef>
#include <cstring>

int main() {
    // 固定模板：兩個屬性，名稱各 2 字元
    const char tmpl[] = "<root XX=\"1\" YY=\"2\"/>";
    const size_t len = sizeof(tmpl); // 含 '\0'
    char input[sizeof(tmpl)];
    memcpy(input, tmpl, len);

    // 僅對 4 個名稱字元做符號化，避免路徑爆炸與矛盾約束
    const int p1[2] = {6, 7};    // 'X''X'
    const int p2[2] = {13, 14};  // 'Y''Y'
    char c1, c2, c3, c4;
    klee_make_symbolic(&c1, 1, "name1_ch0");
    klee_make_symbolic(&c2, 1, "name1_ch1");
    klee_make_symbolic(&c3, 1, "name2_ch0");
    klee_make_symbolic(&c4, 1, "name2_ch1");

    klee_assume(c1 >= 'a' && c1 <= 'c');
    klee_assume(c2 >= 'a' && c2 <= 'c');
    klee_assume(c3 >= 'a' && c3 <= 'c');
    klee_assume(c4 >= 'a' && c4 <= 'c');

    input[p1[0]] = c1;
    input[p1[1]] = c2;
    input[p2[0]] = c3;
    input[p2[1]] = c4;

    // 限制在小字母集合，縮小求解空間
    klee_assume(input[p1[0]] >= 'a' && input[p1[0]] <= 'c');
    klee_assume(input[p1[1]] >= 'a' && input[p1[1]] <= 'c');
    klee_assume(input[p2[0]] >= 'a' && input[p2[0]] <= 'c');
    klee_assume(input[p2[1]] >= 'a' && input[p2[1]] <= 'c');

    // 解析並偵測屬性解析錯誤（重複屬性名稱常見）
    tinyxml2::XMLDocument doc;
    doc.Parse(input);

    if (doc.ErrorID() == tinyxml2::XML_ERROR_PARSING_ATTRIBUTE) {
        klee_assert(0); // 生成使該錯誤成立的 counterexample 種子
    }

    return 0;
}