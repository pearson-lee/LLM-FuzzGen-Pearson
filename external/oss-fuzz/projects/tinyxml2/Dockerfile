# Copyright 2017 Google Inc.
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
FROM gcr.io/oss-fuzz-base/base-builder:latest
RUN apt-get update && apt-get install -y make autoconf automake libtool pkg-config

ARG TINYXML2_COMMIT=8224e427b655b83dae5e2298f1e6919523a78737
RUN git init tinyxml2 && \
    cd tinyxml2 && \
    git remote add origin https://github.com/leethomason/tinyxml2.git && \
    git fetch --depth 1 origin "$TINYXML2_COMMIT" && \
    git checkout --detach FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = "$TINYXML2_COMMIT"
WORKDIR tinyxml2

COPY build.sh *.cpp *.dict *.options $SRC/
COPY llm_fuzzgen* $SRC/
