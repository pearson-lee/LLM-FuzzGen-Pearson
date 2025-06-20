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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool pkg-config

RUN git clone --depth 1 https://github.com/libimobiledevice/libplist && \
    cd libplist && \
    git fetch --depth 1 origin 5ea6de69afcf11f2d2e59258cb055a5b1fdb5f82 && \
    git checkout 5ea6de69afcf11f2d2e59258cb055a5b1fdb5f82

WORKDIR libplist

COPY build.sh *.zip $SRC/
COPY fuzz_*_fuzzer.cc fuzz_*_fuzzer.cpp $SRC/libplist/fuzz/
