# Copyright 2023 Google LLC
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
RUN apt-get update && apt-get install -y cmake make

ARG TOMLPLUSPLUS_COMMIT=1e8829b793b66ad17011732a146b8077d379b011
RUN git init tomlplusplus && \
    cd tomlplusplus && \
    git remote add origin https://github.com/marzer/tomlplusplus.git && \
    git fetch --depth 1 origin "$TOMLPLUSPLUS_COMMIT" && \
    git checkout --detach FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = "$TOMLPLUSPLUS_COMMIT" && \
    cp fuzzing/build.sh $SRC/
WORKDIR tomlplusplus

COPY build.sh *.cpp *.dict *.options $SRC/
COPY llm_fuzzgen* $SRC/
