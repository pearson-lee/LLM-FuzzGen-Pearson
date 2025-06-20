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
# v1.7.18
RUN git clone --depth 1 https://github.com/DaveGamble/cJSON.git cjson && \
    cd cjson && \
    git fetch --depth 1 origin 76be8fcf15677ca7f6db7c770f5ae6bf8b41d78f && \
    git checkout 76be8fcf15677ca7f6db7c770f5ae6bf8b41d78f
WORKDIR cjson
COPY build.sh $SRC/
COPY llm_fuzzgen* $SRC/
