#!/bin/bash -eu
# Copyright 2019 Google Inc.
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


RUN apt-get update && apt-get install -y cmake
ARG CJSON_COMMIT=12c4bf1986c288950a3d06da757109a6aa1ece38
RUN git init cjson && \
    cd cjson && \
    git remote add origin https://github.com/DaveGamble/cJSON.git && \
    git fetch --depth 1 origin "$CJSON_COMMIT" && \
    git checkout --detach FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = "$CJSON_COMMIT"
WORKDIR cjson
COPY build.sh $SRC/
COPY llm_fuzzgen* $SRC/
