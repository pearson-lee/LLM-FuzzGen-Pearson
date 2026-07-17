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
RUN apt-get update && apt-get install -y make autoconf automake libtool cmake nasm
ARG LIBTIFF_COMMIT=fcd4c86c4907d859c3124c8ad786868ba3f0b713
RUN git init libtiff && \
    cd libtiff && \
    git remote add origin https://gitlab.com/libtiff/libtiff.git && \
    git fetch --depth 1 origin "$LIBTIFF_COMMIT" && \
    git checkout --detach FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = "$LIBTIFF_COMMIT"
RUN git clone --depth 1 https://github.com/madler/zlib
RUN git clone --depth 1 https://github.com/libjpeg-turbo/libjpeg-turbo
RUN git clone https://www.cl.cam.ac.uk/~mgk25/git/jbigkit
ADD https://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz afl_testcases.tgz
ADD https://raw.githubusercontent.com/google/AFL/debe27037b9444bbf090a0ffbd5d24889bb887ae/dictionaries/tiff.dict tiff.dict
WORKDIR libtiff
COPY build.sh $SRC/
COPY llm_fuzzgen* $SRC/
