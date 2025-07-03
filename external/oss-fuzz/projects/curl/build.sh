#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

# Run the OSS-Fuzz script in the curl-fuzzer project.
# ./ossfuzz.sh
# Save off the current folder as the build root.
export BUILD_ROOT=$PWD
SCRIPTDIR=${BUILD_ROOT}/scripts

. ${SCRIPTDIR}/fuzz_targets

GDBDIR=/src/gdb

echo "BUILD_ROOT: $BUILD_ROOT"
echo "SRC: ${SRC:-undefined}"
echo "CC: $CC"
echo "CXX: $CXX"
echo "LIB_FUZZING_ENGINE: $LIB_FUZZING_ENGINE"
echo "CFLAGS: $CFLAGS"
echo "CXXFLAGS: $CXXFLAGS"
echo "ARCHITECTURE: $ARCHITECTURE"
echo "FUZZ_TARGETS: $FUZZ_TARGETS"

export MAKEFLAGS+="-j$(nproc)"

# Set the CURL_SOURCE_DIR for the build.
export CURL_SOURCE_DIR=/src/curl

# Compile the fuzzers.
${SCRIPTDIR}/compile_target.sh fuzz

# Zip up the seed corpus.
scripts/create_zip.sh

# Copy the fuzzers over.
for TARGET in $FUZZ_TARGETS
do
  cp -v build/${TARGET} ${TARGET}_seed_corpus.zip $OUT/
done

# Copy dictionary and options file to $OUT.
cp -v ossconfig/*.dict ossconfig/*.options $OUT/
