import os
import glob

def extract_dependencies(log_dir, output_filepath):
    """
    掃描指定目錄下的所有 log 檔案，提取 Dependency 資訊並寫入彙整檔案。
    (已加入依檔名時間戳記排序功能)
    """
    # 取得資料夾下所有的 .log 檔案路徑，並使用 sorted() 進行排序
    log_files = sorted(glob.glob(os.path.join(log_dir, '*.log')))
    
    if not log_files:
        print(f"在 {log_dir} 中找不到任何 .log 檔案。")
        return

    # 開啟共用的輸出檔案 (使用寫入模式 'w')
    with open(output_filepath, 'w', encoding='utf-8') as out_file:
        for filepath in log_files:
            filename = os.path.basename(filepath)
            dependency_value = "Not Found" # 預設值
            
            # 讀取單一 log 檔案內容
            try:
                with open(filepath, 'r', encoding='utf-8') as log_file:
                    for line in log_file:
                        if line.startswith("Dependency:") or "Dependency:" in line:
                            dependency_value = line.split("Dependency:")[1].strip()
                            break 
            except Exception as e:
                print(f"讀取檔案 {filename} 時發生錯誤: {e}")
                continue
            
            # 將結果格式化並寫入共用檔案
            result_line = f"{filename} - Dependency: {dependency_value}\n"
            out_file.write(result_line)
            
    print(f"處理完成！共依序掃描 {len(log_files)} 個檔案，結果已儲存至: {output_filepath}")

# ==========================================
# 執行設定區
# ==========================================
if __name__ == "__main__":
    LOG_DIRECTORY = "./Judge/tinyxml2/change_prompt" 
    OUTPUT_FILE = "all_dependencies_summary.txt"
    
    extract_dependencies(LOG_DIRECTORY, OUTPUT_FILE)