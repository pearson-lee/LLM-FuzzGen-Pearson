#!/bin/bash -eu
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
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
SYMCC_NATIVE_EXPORT_ENABLED="${LLM_FUZZGEN_EXPORT_NATIVE_ARTIFACTS:-0}"

if [ "$BUILD_FLAVOR" = "symcc_replay" ]; then
  SYMCC_REPLAY_ENABLED=1
fi
if [ "$BUILD_FLAVOR" = "symcc_native" ]; then
  SYMCC_NATIVE_EXPORT_ENABLED=1
fi

strip_instrumentation_flags() {
  local raw_flags="$1"
  local filtered_flags=()
  local skip_next=0
  local token

  for token in $raw_flags; do
    if [ "$skip_next" -eq 1 ]; then
      skip_next=0
      case "$token" in
        *sanitizer-coverage*|*sancov*|*libfuzzer*|*fuzzer-no-link*)
          continue
          ;;
      esac
      filtered_flags+=("$token")
      continue
    fi

    case "$token" in
      -fsanitize-coverage=*|-fsanitize=fuzzer|-fsanitize=fuzzer-no-link|-fsanitize=fuzzer-no-link,*|-fsanitize=*fuzzer*)
        continue
        ;;
      -mllvm)
        skip_next=1
        continue
        ;;
      *sanitizer-coverage*|*sancov*)
        continue
        ;;
    esac
    filtered_flags+=("$token")
  done

  printf '%s ' "${filtered_flags[@]}"
}

if [ "$BUILD_FLAVOR" = "symcc_native" ]; then
  export CFLAGS="$(strip_instrumentation_flags "$CFLAGS")"
  export CXXFLAGS="$(strip_instrumentation_flags "$CXXFLAGS")"
  export LDFLAGS="$(strip_instrumentation_flags "${LDFLAGS:-}")"
fi

echo "[llm-fuzzgen] SANITIZER=$SANITIZER BUILD_FLAVOR=$BUILD_FLAVOR" >&2

# Build libvpx
chmod 0644 "$SRC"/vpx_fuzzer_seed_corpus.zip 2>/dev/null || true
chmod 0644 "$SRC"/llm_fuzzgen*_seed_corpus.zip 2>/dev/null || true
build_dir=$WORK/build
rm -rf ${build_dir}
mkdir -p ${build_dir}
pushd ${build_dir}

# oss-fuzz has 2 GB total memory allocation limit. So, we limit per-allocation
# limit in libvpx to 1 GB to avoid OOM errors. A smaller per-allocation is
# needed for MemorySanitizer (see bug oss-fuzz:9497 and bug oss-fuzz:9499).
if [[ $CFLAGS = *sanitize=memory* ]]; then
  extra_c_flags='-DVPX_MAX_ALLOCABLE_MEMORY=536870912'
else
  extra_c_flags='-DVPX_MAX_ALLOCABLE_MEMORY=1073741824'
fi

LDFLAGS="$CXXFLAGS" LD=$CXX $SRC/libvpx/configure \
    --enable-vp9-highbitdepth \
    --disable-unit-tests \
    --disable-examples \
    --size-limit=12288x12288 \
    --extra-cflags="${extra_c_flags}" \
    --disable-webm-io \
    --enable-debug \
    --disable-vp8-encoder \
    --disable-vp9-encoder
make -j$(nproc) all
popd

# build fuzzers
fuzzer_src_name=vpx_dec_fuzzer
fuzzer_decoders=( 'vp9' 'vp8' )
for decoder in "${fuzzer_decoders[@]}"; do
  fuzzer_name=${fuzzer_src_name}"_"${decoder}

  $CXX $CXXFLAGS -std=c++11 \
    -DDECODER=${decoder} \
    -I$SRC/libvpx \
    -I${build_dir} \
    $SRC/libvpx/examples/${fuzzer_src_name}.cc -o $OUT/${fuzzer_name} \
    -Wl,--start-group \
    -Wl,--whole-archive ${build_dir}/libvpx.a -Wl,--no-whole-archive  \
    $LIB_FUZZING_ENGINE \
    -Wl,--end-group

  cp $SRC/vpx_fuzzer_seed_corpus.zip $OUT/${fuzzer_name}_seed_corpus.zip
  chmod 0644 $OUT/${fuzzer_name}_seed_corpus.zip
  cp $SRC/vpx_dec_fuzzer.dict $OUT/${fuzzer_name}.dict
done
SYMCC_REPLAY_DIR="$OUT/symcc_replay"
SYMCC_NATIVE_DIR="$OUT/symcc_native"

REPLAY_DRIVER_SOURCE="$SRC/libvpx_build_replay_driver.cc"
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

  $CXX $CXXFLAGS -D_FUZZ_TARGET_NAME="\"$target_basename\"" -std=c++11 \
    -I$SRC/libvpx -I${build_dir} -c "$target" -o "$target_obj"
  $CXX $CXXFLAGS "$target_obj" -o "$OUT/$target_basename" \
    -Wl,--start-group \
    -Wl,--whole-archive ${build_dir}/libvpx.a -Wl,--no-whole-archive \
    $LIB_FUZZING_ENGINE \
    -Wl,--end-group

  if [ "$SYMCC_REPLAY_ENABLED" = "1" ]; then
    mkdir -p "$SYMCC_REPLAY_DIR"
    $CXX $CXXFLAGS -std=c++11 -I$SRC/libvpx -I${build_dir} \
      -c "$REPLAY_DRIVER_SOURCE" -o "$replay_obj"
    $CXX $CXXFLAGS "$replay_obj" "$target_obj" \
      -o "$SYMCC_REPLAY_DIR/${target_basename}_replay" \
      -Wl,--start-group \
      -Wl,--whole-archive ${build_dir}/libvpx.a -Wl,--no-whole-archive \
      -Wl,--end-group
  fi
}

##### LLM-FuzzGen #####
# Compile llm_fuzzgen*.cc, llm_fuzzgen*.cpp, llm_fuzzgen*.c
find "$SRC" -maxdepth 1 -type f \( -name "llm_fuzzgen*.c" -o -name "llm_fuzzgen*.cc" -o -name "llm_fuzzgen*.cpp" \) -print | while read -r target; do
  target_basename=$(basename "${target%.*}")
  compile_llm_target "$target" "$target_basename"

  if [ -f "$SRC/llm_fuzzgen.dict" ] && [ ! -f "$SRC/${target_basename}.options" ]; then
    echo "[libfuzzer]" > "$SRC/${target_basename}.options"
    echo "dict = llm_fuzzgen.dict" >> "$SRC/${target_basename}.options"
  fi
done
cp $SRC/llm_fuzzgen.dict $OUT/ || true
cp $SRC/llm_fuzzgen*.options $OUT/ || true
cp $SRC/llm_fuzzgen*_seed_corpus.zip $OUT/ || true
chmod 0644 $OUT/llm_fuzzgen*_seed_corpus.zip 2>/dev/null || true
#######################

# Export CLEAN Source Tree For KLEE
PROJECT_NAME="libvpx"
OUT_PROJECT_DIR="$OUT/source_code"

if [ -e "$OUT_PROJECT_DIR" ] && [ ! -d "$OUT_PROJECT_DIR" ]; then
  rm -f "$OUT_PROJECT_DIR"
fi
mkdir -p "$OUT_PROJECT_DIR"

if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete --no-perms \
    --exclude='.git' --exclude='.github' --exclude='.gitignore' \
    --exclude='build' --exclude='cmake' --exclude='CMakeFiles' \
    --exclude='*.o' --exclude='*.a' --exclude='*.so' --exclude='*.dll' \
    "$SRC/libvpx/" "$OUT_PROJECT_DIR/"
else
  find "$SRC/libvpx" -maxdepth 1 -type f \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cc' -o -name '*.cpp' \) \
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

if [ "$SYMCC_NATIVE_EXPORT_ENABLED" = "1" ]; then
  mkdir -p "$SYMCC_NATIVE_DIR/build_headers"
  cp "${build_dir}/libvpx.a" "$SYMCC_NATIVE_DIR/libvpx.a"
  # Export generated headers (vpx_config.h, vpx_version.h, *_rtcd.h, etc.)
  find "${build_dir}" -maxdepth 1 -name "*.h" -exec cp {} "$SYMCC_NATIVE_DIR/build_headers/" \;
  if nm -A "$SYMCC_NATIVE_DIR/libvpx.a" | grep -qE '__sanitizer_cov_|__sancov_'; then
    echo "[llm-fuzzgen] symcc_native archive still contains sanitizer coverage symbols" >&2
    exit 1
  fi
fi
