/**
 * 驗證程式：tomlplusplus_toml_v3_at_path_toml_v3_node_toml_v3_path_const_494 內部不變量反向實證
 * 
 * 測試目的：
 * 證明在 toml++ at_path(node&, const path&) 查詢流程中：
 *   for (const auto& component : path)
 *   {
 *       auto type = component.type();
 *       if (type == path_component_type::array_index) { ... }
 *       else if (type == path_component_type::key) { ... }
 *       else {
 *           // Error: invalid component
 *           return {}; // Line 505 (受阻目標行)
 *       }
 *   }
 * 
 * 核心證明要點：
 * 1. 歷史 LLM 誤判根因（型別解析幻覺）：
 *    歷史 LLM 誤以為提供語法錯誤的路徑字串（如未閉合括號、非法字元）時，
 *    toml::path 解析器會構造出一個既非 key 也非 array_index 的「未知型別組件」，
 *    從而進入 else 分支觸發 Line 505。
 * 
 * 2. 封閉型別系統與解析器狀態機保證：
 *    - enum class path_component_type : uint8_t 屬於封閉列舉，全庫僅定義 key(0x1) 與 array_index(0x2)。
 *    - path_component 的所有建構子保證其 type_ 必為 key 或 array_index，全庫無任何 API 可賦值其他型態。
 *    - 路徑解析器 impl::parse_path 在遇到語法錯誤時直接返回 false 並回滾組件列表，組件數歸零，
 *      絕不可能建立任何無效型別的組件。
 *    - 因此，遍歷 path 中的每一個 component 時，其 type 必命中 array_index 或 key。
 *    - Line 505 的 else 分支在型別系統與邏輯架構下恆不可達，確證為內部防禦性死碼。
 */

#include <iostream>
#include <string>
#include <vector>
#include <cassert>
#include "toml++/toml.hpp"

struct TestCase {
    std::string name;
    std::string path_str;
};

int main() {
    std::cout << "====================================================================\n";
    std::cout << " 驗證程式：tomlplusplus_at_path_494 內部不變量防禦性死碼實證\n";
    std::cout << "====================================================================\n\n";

    // 建立測試用 TOML 表格
    std::string toml_data = R"(
        [servers]
        alpha = { ip = "10.0.0.1", role = "backend" }
        beta  = { ip = "10.0.0.2", role = "frontend" }
        ports = [ 80, 443, 8080 ]
        [servers.matrix]
        nested = [ [ 1, 2 ], [ 3, 4 ] ]
    )";

    auto tbl = toml::parse(toml_data);

    // 測試各種正常、畸變、邊界與非法路徑
    std::vector<TestCase> cases = {
        {"標準鍵路徑", "servers.alpha.ip"},
        {"陣列索引路徑", "servers.ports[1]"},
        {"多維陣列路徑", "servers.matrix.nested[1][0]"},
        {"索引超出範圍", "servers.ports[99]"},
        {"多重連續句點", "servers..alpha"},
        {"未閉合左括號", "servers[alpha"},
        {"連續左括號畸變", "[[[[[["},
        {"連續右括號畸變", "]]]]]]"},
        {"空白路徑", ""},
        {"純句點路徑", "..."},
        {"特殊字元與逸出", "\"quoted.key\""},
        {"陣列當表格查鍵", "servers.ports.invalid_key"}
    };

    std::cout << "[測試 1] 驗證各類路徑字串解析後的 path_component 型別...\n";
    for (size_t i = 0; i < cases.size(); ++i) {
        toml::path p(cases[i].path_str);
        std::cout << "  Case " << i + 1 << " [" << cases[i].name << "]: \"" 
                  << cases[i].path_str << "\" -> 組件數 = " << p.size() << "\n";

        for (size_t j = 0; j < p.size(); ++j) {
            auto comp_type = p[j].type();
            bool is_valid = (comp_type == toml::path_component_type::key || 
                             comp_type == toml::path_component_type::array_index);
            assert(is_valid);
            std::cout << "    Component [" << j << "] 型別: " 
                      << (comp_type == toml::path_component_type::key ? "key (0x1)" : "array_index (0x2)") << "\n";
        }

        // 調用 at_path
        auto result = tbl.at_path(p);
        std::cout << "    at_path 結果: " << (result ? "查詢成功 (Found)" : "查詢為空 (Not Found)") << "\n";
    }

    std::cout << "\n[測試 2] 驗證非法路徑解析時的狀態機回滾機制...\n";
    {
        // 證明：非法路徑不會生成未知型態組件，而是回滾為 0 個組件
        toml::path malformed("invalid[syntax[broken");
        assert(malformed.size() == 0);
        std::cout << "  -> 非法路徑 \"invalid[syntax[broken\" 解析後組件數 = 0 (完全不生成組件)\n";
    }

    std::cout << "\n====================================================================\n";
    std::cout << "【結論】\n";
    std::cout << "在 toml++ 中，所有 path_component 的 type() 嚴格恆為 key 或 array_index。\n";
    std::cout << "進入 at_path 迴圈時，所有組件皆必然命中前兩個 if / else if 分支。\n";
    std::cout << "Line 494/502 的 else 區塊（Line 505: return {};）在型別系統下恆不可達，\n";
    std::cout << "確證為 100% 內部防禦性死碼！\n";
    std::cout << "====================================================================\n";

    return 0;
}
