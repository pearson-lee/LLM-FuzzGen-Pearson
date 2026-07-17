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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y yasm wget gcc
ARG LIBVPX_COMMIT=9514ab684d3680e5180404894809328611179ad1
RUN git init libvpx && \
    cd libvpx && \
    git remote add origin https://chromium.googlesource.com/webm/libvpx && \
    git fetch --depth 1 origin "$LIBVPX_COMMIT" && \
    git checkout --detach FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = "$LIBVPX_COMMIT"
ADD https://storage.googleapis.com/downloads.webmproject.org/test_data/fuzzer/vpx_fuzzer_seed_corpus.zip $SRC/
COPY build.sh vpx_dec_fuzzer.dict $SRC/
WORKDIR libvpx
COPY llm_fuzzgen* $SRC/
