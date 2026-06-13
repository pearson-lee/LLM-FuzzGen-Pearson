##### LLM-FuzzGen #####
export PATH="/ccache/bin:$PATH" # Use ccache for faster builds, from oss-fuzz/infra/base-images/base-builder/Dockerfile
export CCACHE_DIR="$WORK/ccache"
export CFLAGS="$CFLAGS -w -fno-color-diagnostics -fdiagnostics-fixit-info" # Suppress warnings, color diagnostics and fixit info
export CXXFLAGS="$CXXFLAGS -w -fno-color-diagnostics -fdiagnostics-fixit-info" # Suppress warnings, color diagnostics and fixit info
#https://github.com/google/oss-fuzz/pull/10891
#if [ "$SANITIZER" == "introspector" ]; then
#  export CFLAGS="${CFLAGS} -fsanitize=address"
#  export CXXFLAGS="${CXXFLAGS} -fsanitize=address"
#fi
#https://github.com/google/oss-fuzz/pull/12356
if [ "$SANITIZER" == "introspector" ]; then
  export CFLAGS=$(echo "$CFLAGS" | sed 's/gold/lld/g')
  export CXXFLAGS=$(echo "$CXXFLAGS" | sed 's/gold/lld/g')
fi
#######################
BUILD_FLAVOR="${LLM_FUZZGEN_BUILD_FLAVOR:-default}"
SYMCC_REPLAY_ENABLED="${LLM_FUZZGEN_BUILD_SYMCC_REPLAY:-0}"

if [ "$BUILD_FLAVOR" = "symcc_replay" ]; then
  SYMCC_REPLAY_ENABLED=1
fi

echo "[llm-fuzzgen] SANITIZER=$SANITIZER BUILD_FLAVOR=$BUILD_FLAVOR" >&2

cd $SRC/tomlplusplus
mkdir -p build
cmake -S . -B build -DBUILD_FUZZER=ON && cmake --build build --target install

# Build the corpus using the existing toml files in the source
mkdir -p corpus
find $SRC/tomlplusplus -name "*.toml" -exec cp {} corpus \;
zip -q -j $OUT/toml_fuzzer_seed_corpus.zip corpus/*

SYMCC_REPLAY_DIR="$OUT/symcc_replay"

REPLAY_DRIVER_SOURCE="$SRC/tomlplusplus_build_replay_driver.cc"
cat > "$REPLAY_DRIVER_SOURCE" <<'EOF'
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

static bool ReadAllBytes(FILE* input, std::vector<uint8_t>* data) {
  if (!input || !data) {
    return false;
  }

  constexpr size_t kChunkSize = 4096;
  std::vector<uint8_t> buffer;
  uint8_t chunk[kChunkSize];

  for (;;) {
    size_t count = fread(chunk, 1, sizeof(chunk), input);
    if (count > 0) {
      buffer.insert(buffer.end(), chunk, chunk + count);
    }
    if (count < sizeof(chunk)) {
      if (feof(input)) {
        break;
      }
      return false;
    }
  }

  data->swap(buffer);
  return true;
}

int main(int argc, char** argv) {
  FILE* input = stdin;
  std::vector<uint8_t> data;

  if (argc > 2) {
    fprintf(stderr, "usage: %s [seed-file]\n", argv[0]);
    return 1;
  }

  if (argc == 2) {
    input = fopen(argv[1], "rb");
    if (!input) {
      perror("fopen");
      return 1;
    }
  }

  if (!ReadAllBytes(input, &data)) {
    fprintf(stderr, "failed to read input\n");
    if (argc == 2) {
      fclose(input);
    }
    return 1;
  }

  if (argc == 2) {
    fclose(input);
  }

  return LLVMFuzzerTestOneInput(data.data(), data.size());
}
EOF

compile_llm_target() {
  local target="$1"
  local target_basename="$2"
  local target_obj="${target_basename}.o"
  local replay_obj="${target_basename}_replay_driver.o"

  $CXX $CXXFLAGS -D_FUZZ_TARGET_NAME="\"$target_basename\"" -std=c++17 -DNDEBUG \
    -I$SRC/tomlplusplus/include \
    -c "$target" -o "$target_obj"
  $CXX $CXXFLAGS "$target_obj" -o "$OUT/$target_basename" $LIB_FUZZING_ENGINE

  if [ "$SYMCC_REPLAY_ENABLED" = "1" ]; then
    mkdir -p "$SYMCC_REPLAY_DIR"
    $CXX $CXXFLAGS -std=c++17 -DNDEBUG -I$SRC/tomlplusplus/include \
      -c "$REPLAY_DRIVER_SOURCE" -o "$replay_obj"
    $CXX $CXXFLAGS "$replay_obj" "$target_obj" \
      -o "$SYMCC_REPLAY_DIR/${target_basename}_replay"
  fi
}

##### LLM-FuzzGen #####
# Compile llm_fuzzgen*.cc, llm_fuzzgen*.cpp, llm_fuzzgen*.c
find "$SRC" -maxdepth 1 -type f \( -name "llm_fuzzgen*.c" -o -name "llm_fuzzgen*.cc" -o -name "llm_fuzzgen*.cpp" \) -print | while read -r target; do
  target_basename=$(basename "${target%.*}")

  compile_llm_target "$target" "$target_basename"
  ####

  if [ -f "$SRC/llm_fuzzgen.dict" ] && [ ! -f "$SRC/${target_basename}.options" ]; then
    echo "[libfuzzer]" > "$SRC/${target_basename}.options"
    echo "dict = llm_fuzzgen.dict" >> "$SRC/${target_basename}.options"
  fi
done
cp $SRC/llm_fuzzgen.dict $OUT/ || true
cp $SRC/llm_fuzzgen*.options $OUT/ || true
cp $SRC/llm_fuzzgen*_seed_corpus.zip $OUT/ || true
#######################

# Export CLEAN Source Tree For KLEE
PROJECT_NAME="tomlplusplus"
OUT_PROJECT_DIR="$OUT/source_code"

# Ensure clean dir (and avoid "file exists" if a file was created by mistake)
if [ -e "$OUT_PROJECT_DIR" ] && [ ! -d "$OUT_PROJECT_DIR" ]; then
  rm -f "$OUT_PROJECT_DIR"
fi
mkdir -p "$OUT_PROJECT_DIR"

# copy source files
if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete --no-perms \
    --exclude='.git' --exclude='.github' --exclude='.gitignore' \
    --exclude='build' --exclude='cmake' --exclude='CMakeFiles' \
    --exclude='*.o' --exclude='*.a' --exclude='*.so' --exclude='*.dll' \
    "$SRC/tomlplusplus/" "$OUT_PROJECT_DIR/"
else
  find "$SRC/tomlplusplus" -maxdepth 1 -type f \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cc' -o -name '*.cpp' \) \
    -exec cp {} "$OUT_PROJECT_DIR/" \;
fi

# copy include directory if exists
if [ -d "$SRC/include" ]; then
  rsync -a --delete --no-perms "$SRC/include/" "$OUT_PROJECT_DIR/include/" 2>/dev/null || \
    { mkdir -p "$OUT_PROJECT_DIR/include"; cp -r "$SRC/include/." "$OUT_PROJECT_DIR/include/"; }
fi

# copy klee harness files if present
find "$SRC" -maxdepth 1 -type f \( -name "klee_*.c" -o -name "klee_*.cpp" \) \
  -exec cp {} "$OUT_PROJECT_DIR/" \;
