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

cd $SRC/tomlplusplus
mkdir -p build
cmake -S . -B build -DBUILD_FUZZER=ON && cmake --build build --target install

# Build the corpus using the existing toml files in the source
mkdir -p corpus
find $SRC/tomlplusplus -name "*.toml" -exec cp {} corpus \;
zip -q -j $OUT/toml_fuzzer_seed_corpus.zip corpus/*

##### LLM-FuzzGen #####
# Compile llm_fuzzgen*.cc, llm_fuzzgen*.cpp, llm_fuzzgen*.c
find "$SRC" -maxdepth 1 -type f \( -name "llm_fuzzgen*.c" -o -name "llm_fuzzgen*.cc" -o -name "llm_fuzzgen*.cpp" \) -print | while read -r target; do
  target_basename=$(basename "${target%.*}")

  #### compile the fuzz target (for tomlplusplus)
  $CXX $CXXFLAGS -D_FUZZ_TARGET_NAME="\"$target_basename\"" -std=c++17 -DNDEBUG \
    -I$SRC/tomlplusplus/include \
    "$target" -o "$OUT/${target_basename}" \
    $LIB_FUZZING_ENGINE
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
