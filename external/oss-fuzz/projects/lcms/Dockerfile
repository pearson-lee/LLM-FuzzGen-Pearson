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
ARG LCMS_COMMIT=04ace9c100fc6850f09223dd6c7ad8fa634acd06

RUN git init lcms && \
    cd lcms && \
    git remote add origin https://github.com/mm2/Little-CMS.git && \
    git fetch --depth 1 origin "$LCMS_COMMIT" && \
    git checkout --detach FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = "$LCMS_COMMIT"

RUN mkdir $SRC/seeds && \
    cd seeds && \
    cp $SRC/lcms/testbed/bad.icc . && \
    cp $SRC/lcms/testbed/toosmall.icc . && \
    cp $SRC/lcms/testbed/test1.icc . && \
    cp $SRC/lcms/testbed/crayons.icc . && \
    cp $SRC/lcms/testbed/ibm-t61.icc . && \
    zip -rj $SRC/seed_corpus.zip $SRC/seeds/*

WORKDIR lcms
COPY build.sh *.c *.options *.dict $SRC/
COPY llm_fuzzgen* $SRC/
