// 驗證程式：tomlplusplus operator<(date_time, date_time)  date_time.hpp:416 -> 417
//
// 目標：證明在「不修改」fuzz target（llm_fuzzgen0727161637）的前提下，
//       存在一組 fuzzer 輸入 bytes 可使 Line 416 `if (lhs.time != rhs.time)` 為 TRUE，
//       並實際執行 Line 417 `return lhs.time < rhs.time;`。
//
// 做法：
//   1. 本檔直接 #include 案例目錄中原封不動的 fuzz_target.cc（與
//      external/oss-fuzz/projects/tomlplusplus/llm_fuzzgen0727161637.cc 逐字相同）。
//      harness 內的絕對路徑 include（/src/tomlplusplus/...）由 run_verify.sh 以
//      clang -ivfsoverlay 重新導向至 external/tomlplusplus，harness 原始碼不做任何改動。
//   2. SeedBuilder 依照 FuzzedDataProvider 的消耗語意精確構造 byte stream：
//        - ConsumeRandomLengthString 從 buffer「前端」取字元；
//        - ConsumeIntegralInRange / ConsumeBool 從 buffer「尾端」取位元組，
//          多位元組整數中「先被取出的位元組為高位」。
//      因此 seed = [TOML 文字][padding][尾端控制位元組（依消耗順序反轉）]。
//   3. 以 clang source-based coverage 量測每顆 seed 對 Line 414/416/417 的實際 hit count。
//
// 用法（由 run_verify.sh 呼叫）：
//   verify_poc emit <out_dir>   產生 3 顆 seed 並印出 FDP 重建的 TOML 文字
//   verify_poc <seed_file>      以 harness 的 LLVMFuzzerTestOneInput 重播該 seed

#include "fuzz_target.cc"

#include <cstdio>
#include <cstdlib>
#include <iterator>

namespace {

// harness 第 20–89 行，15 個附加 TOML 片段的 ConsumeBool 依序索引
constexpr int kAppendLdt = 7;   // line 50: ldt1 = 1979-05-27T07:32:00 / ldt2 = 1981-02-10T10:00:00
constexpr int kAppendOdt = 8;   // line 54: odt1 = 1979-05-27T07:32:00-07:00 / odt2 = 1981-02-10T10:00:00-05:00
constexpr int kAppendCount = 15;

class SeedBuilder {
 public:
  explicit SeedBuilder(std::string toml) : toml_(std::move(toml)) {
    if (toml_.find('\\') != std::string::npos || toml_.size() > 1024) {
      std::fprintf(stderr, "TOML 文字不可含反斜線且長度需 <= 1024\n");
      std::exit(2);
    }
  }

  void Bool(bool v) { tail_.push_back(v ? 0x01 : 0x00); }

  // ConsumeIntegralInRange：先取出的位元組為高位，結果再對 (range+1) 取餘數
  void Integral(uint64_t value, int num_bytes) {
    for (int i = num_bytes - 1; i >= 0; --i) tail_.push_back(static_cast<uint8_t>(value >> (8 * i)));
  }

  // 依照 harness 第 18–352 行的實際控制流程，編碼所有尾端消耗
  void EncodeHarnessPath(const std::vector<int>& enabled_appends, int date_time_nodes) {
    Integral(toml_.size(), 2);                       // line 18: ConsumeIntegralInRange<size_t>(0, 1024) -> 2 bytes
    for (int i = 0; i < kAppendCount; ++i)           // line 20–89: 15 個附加片段開關
      Bool(std::find(enabled_appends.begin(), enabled_appends.end(), i) != enabled_appends.end());
    Integral(0, 1);                                  // line 97: parse_mode = ConsumeIntegralInRange(0, 3) -> 0 (toml::parse)
    for (int i = 0; i < 8; ++i) Bool(false);         // line 127,137,141,145,157,175,179,187：不做輸出/erase/clear

    // 走訪迴圈：root table
    for (int i = 0; i < 5; ++i) Bool(false);         // line 209–214
    Bool(false);                                     // line 218: 不 prune
    // 每個 date_time value 節點
    for (int n = 0; n < date_time_nodes; ++n) {
      for (int i = 0; i < 5; ++i) Bool(false);       // line 209–214
      for (int i = 0; i < 7; ++i) Bool(false);       // line 304,306,308,310,312,314,316
      Bool(false);                                   // line 317: as_date_time() 非空 -> 消耗 1 次
      Bool(false); Bool(false);                      // line 325: 兩次 ConsumeBool
      if (n > 0)                                     // line 346–348：第一個節點只 emplace，其後才比較
        for (int i = 0; i < 6; ++i) Bool(true);      //   ==, !=, <, <=, >, >= 全部開啟（< 與 >= 皆會呼叫 operator<）
    }
  }

  std::vector<uint8_t> Build() const {
    std::vector<uint8_t> out(toml_.begin(), toml_.end());
    out.insert(out.end(), 4, 0x00);  // padding：走訪迴圈需 remaining_bytes() > 2；迴圈後剩 4 bytes，跳過 line 358/376 區塊
    out.insert(out.end(), tail_.rbegin(), tail_.rend());
    return out;
  }

 private:
  std::string toml_;
  std::vector<uint8_t> tail_;
};

struct SeedSpec {
  const char* name;
  const char* purpose;
  std::string random_toml;          // line 18 ConsumeRandomLengthString 取得的內容
  std::vector<int> enabled_appends; // 開啟的 harness 硬編碼片段
  int date_time_nodes;              // 解析後 table 中 date_time 節點數
};

std::vector<SeedSpec> Specs() {
  return {
      {"seed0_negative_control",
       "對照組：僅開啟 harness 硬編碼的 ldt/odt 片段（重現歷史狀態）。同日期配對 ldt2/odt2 的時間也相同，預期 416 有 hit、417 = 0",
       "", {kAppendLdt, kAppendOdt}, 4},
      {"seed1_minimal",
       "最小 POC：random string 直接提供兩個同日期、不同時間的 local date-time",
       "a = 2024-01-01T10:00:00\nb = 2024-01-01T12:00:00\n", {}, 2},
      {"seed2_with_hardcoded",
       "貼近 fuzzer 實際解法：random string 只提供 1 個值，與 harness 硬編碼 ldt1 同日期不同時間",
       "x = 1979-05-27T08:00:00\n", {kAppendLdt}, 3},
  };
}

std::string ReconstructTomlViaFdp(const std::vector<uint8_t>& seed) {
  FuzzedDataProvider fdp(seed.data(), seed.size());
  return fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 1024));
}

int Emit(const std::string& out_dir) {
  for (const auto& spec : Specs()) {
    SeedBuilder b(spec.random_toml);
    b.EncodeHarnessPath(spec.enabled_appends, spec.date_time_nodes);
    std::vector<uint8_t> seed = b.Build();

    std::string path = out_dir + "/" + spec.name + ".bin";
    std::ofstream(path, std::ios::binary).write(reinterpret_cast<const char*>(seed.data()), seed.size());

    std::string reconstructed = ReconstructTomlViaFdp(seed);
    if (reconstructed != spec.random_toml) {
      std::fprintf(stderr, "[錯誤] %s：FDP 重建的 TOML 與預期不符\n", spec.name);
      return 1;
    }
    std::printf("[%s] %zu bytes -> %s\n  用途：%s\n  FDP 重建 random string：%s\n", spec.name, seed.size(),
                path.c_str(), spec.purpose, reconstructed.empty() ? "(空字串)" : ("\n    " + reconstructed).c_str());
  }
  return 0;
}

int Replay(const char* path) {
  std::ifstream in(path, std::ios::binary);
  std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return LLVMFuzzerTestOneInput(data.data(), data.size());
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 3 && std::string(argv[1]) == "emit") return Emit(argv[2]);
  if (argc == 2) return Replay(argv[1]);
  std::fprintf(stderr, "usage: %s emit <out_dir> | %s <seed_file>\n", argv[0], argv[0]);
  return 2;
}
