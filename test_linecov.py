#!/usr/bin/env python3
import logging
from external.oss_fuzz import OSSFuzz
from external.introspector import Introspector
# 設定 Logging，才看得到過程中編譯或執行的動作
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def main():
    oss_fuzz = OSSFuzz()
    introspector = Introspector()
    # 測試參數
    project_name = "tinyxml2"
    fuzzer_name = "xmltest2" 
    # 替換成你想觀察的待測專案「目標函數名稱」，或是 None 代表整個專案
    # function_regex = "_ZN8tinyxml211XMLDocument8IdentifyEPcPPNS_7XMLNodeEb" 
    func_name = "tinyxml2::XMLDocument::Identify(char*, tinyxml2::XMLNode**, bool)"
    
    func_name_list = introspector.get_all_functions("tinyxml2")
    function_regex = ""
    for func in func_name_list:
        # 把兩邊的空格都移除後再比對
        target_name = func.get('function_name', '').replace(' ', '')
        query_name = func_name.replace(' ', '')
        
        if target_name == query_name:
            function_regex = func.get('raw_function_name', '')
            break  # 找到了就提早離開迴圈

    if function_regex:
        print(f"find {func_name}  Regex: {function_regex}")
    else:
        print(f"not found")

    # with open('/home/kyliechien/LLM-FuzzGen/func_names.txt', 'w') as f:
    #     for func in func_name_list:  # 這裡要改成 func_name_list
    #         # 取得你要的欄位，如果沒有則給空字串
    #         raw_name = func.get('raw_function_name', '')
    #         demangled_name = func.get('function_name', '')
            
    #         # 把資訊寫進檔案裡 (例如同時寫入 raw name 和原始名稱方便對照)
    #         f.write(f"Raw: {raw_name} | Demangled: {demangled_name}\n")

    print(f"==================================================")
    print(f" 開始為專案 '{project_name}' 測試單一 Fuzzer: '{fuzzer_name}'")
    print(f" 觀察目標函數: '{function_regex}'")
    print(f"==================================================")
    
    print("start linecov_reports\n")
    

    # 2. 測試執行：呼叫 linecov_reports
    # 它底層會自動去編譯這個 Fuzzer、產生 Coverage Report 並把特定 function 濾出來
    # report = oss_fuzz.linecov_reports(
    #     proj_name=project_name, 
    #     fuzzer_name=fuzzer_name, 
    #     fun_name_regex=function_regex
    # )
    
    report = oss_fuzz.proj_linecov_reports(
        proj_name=project_name, 
        fun_name_regex=function_regex
        )


    print("\n" + "="*50)
    print(f" 覆蓋率報告結果 (Fuzzer: {fuzzer_name} -> {function_regex}):")
    print("="*50)
    
    if report:
        print(report)
    else:
        print(f"這個 Fuzzer 沒有拿到 {function_regex} 的報告。")
        print("可能原因：")
        print("  1. Fuzzer 本身的邏輯根本沒有呼叫到這支函數。")
        print("  2. Fuzzer 是空的，什麼都沒執行。")
        print("  3. function 名稱打錯了。")
        
    print("="*50)


if __name__ == "__main__":
    main()