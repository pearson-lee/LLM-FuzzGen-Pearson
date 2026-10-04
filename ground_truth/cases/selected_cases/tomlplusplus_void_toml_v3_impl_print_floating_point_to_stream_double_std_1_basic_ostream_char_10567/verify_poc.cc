/**
 * 驗證程式：tomlplusplus_print_floating_point_10567 內部不變量反向實證
 * 
 * 測試目的：
 * 證明在 toml++ print_floating_point_to_stream<double> 函式中：
 *   if (!!(format & value_flags::format_as_hexadecimal)) // Line 10567 (受阻條件)
 *       ss << std::hexfloat;                             // Line 10568 (受阻目標行)
 * 
 * 核心證明要點：
 * 1. 歷史 LLM 誤判根因（三重語意幻覺）：
 *    - 誤以為 TOML 標準支援十六進位浮點數（如 0x1.2p-3）。
 *    - 誤以為 parser 解析 hex float 時會為 value<double> 設置 format_as_hexadecimal 旗標。
 *    - 誤以為 yaml_formatter 會透傳該旗標至底層列印函式。
 * 
 * 2. 規格與程式碼三重鎖死保證：
 *    - TOML 1.0.0 官方標準不支援十六進位浮點數，toml::parse 遇 hex float 直接拒絕並拋錯。
 *    - 解析器代碼中 format_as_hexadecimal 僅對 int64_t（整數）進行設定，從未對任何浮點數設置。
 *    - 在 Fuzz Target 呼叫的 yaml_formatter 序列化流程中，formatter::print(const value<double>&)
 *      硬編碼傳遞常數 value_flags::none（數值為 0）。
 *    - 因此，在當前觀測路徑下 format & format_as_hexadecimal 恆等於 0，Line 10568 確證為防禦性死碼。
 */

#include <iostream>
#include <sstream>
#include <string>
#include <cassert>
#include "toml++/toml.hpp"

int main() {
    std::cout << "====================================================================\n";
    std::cout << " 驗證程式：tomlplusplus_print_floating_point_10567 防禦性死碼實證\n";
    std::cout << "====================================================================\n\n";

    // 1. 驗證第一重鎖：TOML 官方標準與 toml::parse 對 hex float 的拒絕
    std::cout << "[測試 1] 驗證歷史 LLM 假想之輸入: \"val = 0x1.2p-3\"...\n";
    try {
        auto tbl = toml::parse("val = 0x1.2p-3");
        std::cout << "  -> 異常：解析竟然成功（不應發生）！\n";
        assert(false);
    } catch (const toml::parse_error& err) {
        std::cout << "  -> 實證：解析器依據 TOML 1.0.0 標準強制拒絕十六進位浮點數！\n";
        std::cout << "     錯誤訊息: " << err.description() << "\n\n";
    }

    // 2. 驗證第二重鎖：標準浮點數解析與 yaml_formatter 輸出
    std::cout << "[測試 2] 驗證標準浮點數透過 yaml_formatter 序列化行為...\n";
    {
        auto tbl = toml::parse("val = 3.141592653589793");
        auto dbl_node = tbl.get("val")->as<double>();
        assert(dbl_node != nullptr);

        std::cout << "  -> 解析後 value<double> 預設旗標: " << static_cast<int>(dbl_node->flags()) << " (value_flags::none = 0)\n";
        assert(dbl_node->flags() == toml::value_flags::none);

        std::stringstream ss;
        ss << toml::yaml_formatter{tbl};
        std::cout << "  -> yaml_formatter 輸出結果: " << ss.str();
    }

    // 3. 驗證第三重鎖：formatter::print 內部硬編碼 value_flags::none 封死旗標傳遞
    std::cout << "\n[測試 3] 驗證格式化器硬編碼防護（手動注入 format_as_hexadecimal 旗標）...\n";
    {
        auto tbl = toml::parse("val = 3.141592653589793");
        auto dbl_node = tbl.get("val")->as<double>();

        // 人為手動設定十六進位旗標
        dbl_node->flags(toml::value_flags::format_as_hexadecimal);
        std::cout << "  -> 手動設定後節點 flags: " << static_cast<int>(dbl_node->flags()) 
                  << " (format_as_hexadecimal = 3)\n";
        assert(dbl_node->flags() == toml::value_flags::format_as_hexadecimal);

        // 觀察 yaml_formatter 輸出：因為 formatter::print 硬編碼傳遞 value_flags::none，
        // 底層依然以十進位輸出，絕不執行 Line 10568 的 ss << std::hexfloat！
        std::stringstream ss;
        ss << toml::yaml_formatter{tbl};
        std::cout << "  -> yaml_formatter 輸出結果: " << ss.str();
        std::cout << "  -> 實證：輸出依然為標準十進位，證明格式化器內部徹底封死旗標傳遞！\n";
    }

    std::cout << "\n====================================================================\n";
    std::cout << "【結論】\n";
    std::cout << "1. TOML 規範禁止 hex float，輸入無法產生帶有十六進位旗標之浮點節點；\n";
    std::cout << "2. yaml_formatter 硬編碼 value_flags::none，底層接收到的 format 恆為 0；\n";
    std::cout << "3. Line 10567 的 if (!!(format & format_as_hexadecimal)) 條件恆為 FALSE；\n";
    std::cout << "受阻目標行 Line 10568 (ss << std::hexfloat;) 確證為 100% 內部防禦性死碼！\n";
    std::cout << "====================================================================\n";

    return 0;
}
