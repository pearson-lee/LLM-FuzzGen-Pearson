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
RUN apt-get update && apt-get install -y make autoconf automake libtool
ARG ZLIB_COMMIT=5a82f71ed1dfc0bec044d9702463dbdf84ea3b71
RUN git init zlib && \
    cd zlib && \
    git remote add origin https://github.com/madler/zlib.git && \
    git fetch --depth 1 origin "$ZLIB_COMMIT" && \
    git checkout --detach FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = "$ZLIB_COMMIT"
WORKDIR zlib
COPY build.sh *_fuzzer.c* $SRC/
COPY llm_fuzzgen* $SRC/
