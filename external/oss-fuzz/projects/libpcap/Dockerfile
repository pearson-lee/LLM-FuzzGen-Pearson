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
RUN apt-get update && apt-get install -y make cmake flex bison
ARG LIBPCAP_COMMIT=2559282f3db683e03cd29d30ab5947d6e14a6500
RUN git init libpcap && \
    cd libpcap && \
    git remote add origin https://github.com/the-tcpdump-group/libpcap.git && \
    git fetch --depth 1 origin "$LIBPCAP_COMMIT" && \
    git checkout --detach FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = "$LIBPCAP_COMMIT"

# for corpus as wireshark
RUN git clone --depth=1 https://github.com/the-tcpdump-group/tcpdump.git tcpdump
WORKDIR $SRC
COPY build.sh $SRC/
COPY llm_fuzzgen* $SRC/
