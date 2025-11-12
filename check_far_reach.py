# #!/usr/bin/env python3
# import datetime
# import json
# import sys
# import os
# from external.introspector import Introspector

# def inspect_far_reach_low_coverage(project_name, output_file=None):
#     """
#     檢查指定專案的 far reach but low coverage 區域，
#     過濾出 reached_by_fuzzers 不為空的項目，並輸出 JSON 結果到文件
#     """
#     # 如果沒有指定輸出文件名，則自動生成
#     if output_file is None:
#         timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
#         output_file = f"{project_name}_reached_funcs_{timestamp}.txt"
    
#     # 初始化 Introspector
#     introspector = Introspector()
    
#     # 啟動 web 應用，這是使用 API 的前提
#     print(f"正在啟動 Introspector webapp 進行 {project_name} 專案分析...")
#     if not introspector.update_start_webapp():
#         print("Failed to start introspector webapp")
#         return
    
#     try:
#         # 獲取 far reach but low coverage 的區域
#         far_reach_data = introspector.check_far_reach_low_coverage(project_name)
        
#         # 過濾出 reached_by_fuzzers 不為空的項目
#         reached_functions = []
#         if "functions" in far_reach_data:
#             for func in far_reach_data["functions"]:
#                 if func.get("reached_by_fuzzers") and len(func.get("reached_by_fuzzers", [])) > 0:
#                     reached_functions.append(func)
        
#         # 創建要保存的結果
#         result = {
#             "project": project_name,
#             "timestamp": datetime.datetime.now().isoformat(),
#             "total_functions": len(far_reach_data.get("functions", [])),
#             "reached_functions": len(reached_functions),
#             "functions": reached_functions
#         }
        
#         # 將結果轉換為漂亮的 JSON 格式並打印
#         print(f"\n找到 {len(reached_functions)} 個已被 fuzzer 觸及的函數（總共 {len(far_reach_data.get('functions', []))} 個函數）")
        
#         # 顯示部分函數信息
#         if reached_functions:
#             print("\n===== 已被 fuzzer 觸及的函數示例 =====")
#             for i, func in enumerate(reached_functions[:5], 1):  # 只顯示前5個
#                 print(f"{i}. {func.get('function_signature', 'Unknown')}")
#                 print(f"   觸及的 fuzzers: {', '.join(func.get('reached_by_fuzzers', []))}")
#             if len(reached_functions) > 5:
#                 print(f"...以及其他 {len(reached_functions) - 5} 個函數")
        
#         # 將結果保存到文件
#         with open(output_file, 'w', encoding='utf-8') as f:
#             f.write(f"# 已被 fuzzer 觸及的函數 - {project_name}\n")
#             f.write(f"# 生成時間: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
#             f.write(f"# 總計: {len(reached_functions)} 個已被觸及的函數 (總共 {len(far_reach_data.get('functions', []))} 個函數)\n\n")
#             json.dump(result, f, indent=2)
        
#         print(f"\n結果已保存到: {os.path.abspath(output_file)}")
        
#     except Exception as e:
#         print(f"Error: {e}")
#         import traceback
#         traceback.print_exc()
#     finally:
#         # 詢問用戶是否關閉伺服器
#         user_input = input("Do you want to shutdown the server? (y/n): ")
#         if user_input.lower() == "y":
#             introspector.shutdown_webapp()
#             print("Server shutdown.")
#         else:
#             print("Server is still running on http://localhost:8080")

# if __name__ == "__main__":
#     if len(sys.argv) < 2:
#         print("Usage: python check_far_reach.py <project_name> [output_file]")
#         sys.exit(1)
    
#     project_name = sys.argv[1]
#     output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
#     inspect_far_reach_low_coverage(project_name, output_file)

#!/usr/bin/env python3
import json
import sys
import os
from datetime import datetime
from external.introspector import Introspector

def check_far_reach_low_coverage(project_name, output_file=None):
    """
    使用 Introspector 查詢 far reach but low coverage 的函數，
    顯示結果並將 JSON 輸出到文件
    
    Args:
        project_name: 專案名稱
        output_file: 輸出文件名稱，若為 None 則自動生成
    """
    # 如果沒有指定輸出文件名，則自動生成
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"{project_name}_far_reach_{timestamp}.txt"
    
    # 初始化 Introspector
    introspector = Introspector()
    
    # 啟動 webapp (這是使用 API 的必要前提)
    print(f"正在啟動 Introspector webapp 進行 {project_name} 專案分析...")
    if not introspector.update_start_webapp():
        print("啟動 webapp 失敗")
        return
    
    try:
        # 使用 target_functions 方法獲取 far reach but low coverage 的函數
        print(f"正在查詢 {project_name} 的 far reach but low coverage 函數...")
        targets = introspector.target_functions(project_name)
        
        # 也可以使用 check_far_reach_low_coverage 獲取更詳細的原始 API 回應
        detailed_response = introspector.check_far_reach_low_coverage(project_name)
        
        # 格式化輸出 JSON 結果到屏幕
        formatted_json = json.dumps(targets, indent=2)
        print("\n===== Far Reach But Low Coverage 函數 =====")
        print(formatted_json)
        print(f"\n找到 {len(targets)} 個目標函數")
        
        # 顯示部分細節資訊
        if targets:
            print("\n===== 函數簽名摘要 =====")
            for idx, target in enumerate(targets, 1):
                print(f"{idx}. {target['function_signature']}")
                if target['possible_header_files']:
                    print(f"   可能的標頭檔: {', '.join(target['possible_header_files'])}")
                print()
        
        # 將結果輸出到文件
        with open(output_file, 'w', encoding='utf-8') as f:
            # 寫入基本信息
            f.write(f"Far Reach But Low Coverage 分析結果 - {project_name}\n")
            f.write(f"生成時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # 寫入簡化的目標函數列表
            f.write("===== 目標函數列表 =====\n")
            f.write(json.dumps(targets, indent=2))
            f.write("\n\n")
            
            # 寫入詳細的 API 回應
            f.write("===== 詳細 API 回應 =====\n")
            f.write(json.dumps(detailed_response, indent=2))
        
        print(f"\n分析結果已保存到文件: {os.path.abspath(output_file)}")
        
    except Exception as e:
        print(f"發生錯誤: {e}")
    finally:
        # 詢問用戶是否關閉伺服器
        user_input = input("是否關閉 Introspector webapp？ (y/n): ")
        if user_input.lower() == "y":
            introspector.shutdown_webapp()
            print("已關閉 webapp")
        else:
            print("Introspector webapp 仍在運行於 http://localhost:8080")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python check_far_reach.py <project_name> [output_file]")
        sys.exit(1)
    
    project_name = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    check_far_reach_low_coverage(project_name, output_file)