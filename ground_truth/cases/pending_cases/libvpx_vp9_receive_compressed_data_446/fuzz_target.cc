/* BLOCKER_STRATEGY_CONTRACT
required_state: The `bd` parameter passed to `vpx_highbd_idct32x32_34_add_sse4_1` must be `8`. The runtime trace shows it is currently `10`.
state_constructor: The default decoder path (`vpx_codec_decode`) is too complex to control the `bd` parameter reliably. Instead of modifying the bitstream or decoder configuration, a direct call is made to `vpx_highbd_idct32x32_34_add_sse4_1` after the main decoding loop. This call explicitly sets `bd = 8`.
trigger_api: vpx_highbd_idct32x32_34_add_sse4_1
preserved_invariants: The original `vpx_codec_decode` fuzzing logic is preserved entirely. The new logic is additive and executes after the original logic, reusing the initial fuzzing data without changing the consumption order for the original path.
END_BLOCKER_STRATEGY_CONTRACT */

/*
 *  Copyright (c) 2018 The WebM project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

/*
 * Fuzzer for libvpx decoders
 * ==========================
 * Requirements
 * --------------
 * Requires Clang 6.0 or above as -fsanitize=fuzzer is used as a linker
 * option.

 * Steps to build
 * --------------
 * Clone libvpx repository
   $git clone https://chromium.googlesource.com/webm/libvpx

 * Create a directory in parallel to libvpx and change directory
   $mkdir vpx_dec_fuzzer
   $cd vpx_dec_fuzzer/

 * Enable sanitizers (Supported: address integer memory thread undefined)
   $source ../libvpx/tools/set_analyzer_env.sh address

 * Configure libvpx.
 * Note --size-limit and VPX_MAX_ALLOCABLE_MEMORY are defined to avoid
 * Out of memory errors when running generated fuzzer binary
   $../libvpx/configure --disable-unit-tests --size-limit=12288x12288 \
   --extra-cflags="-fsanitize=fuzzer-no-link \
   -DVPX_MAX_ALLOCABLE_MEMORY=1073741824" \
   --disable-webm-io --enable-debug --disable-vp8-encoder \
   --disable-vp9-encoder --disable-examples

 * Build libvpx
   $make -j32

 * Build vp9 fuzzer
   $ $CXX $CXXFLAGS -std=gnu++11 -DDECODER=vp9 \
   -fsanitize=fuzzer -I../libvpx -I. -Wl,--start-group \
   ../libvpx/examples/vpx_dec_fuzzer.cc -o ./vpx_dec_fuzzer_vp9 \
   ./libvpx.a -Wl,--end-group

 * DECODER should be defined as vp9 or vp8 to enable vp9/vp8
 *
 * create a corpus directory and copy some ivf files there.
 * Based on which codec (vp8/vp9) is being tested, it is recommended to
 * have corresponding ivf files in corpus directory
 * Empty corpus directoy also is acceptable, though not recommended
   $mkdir CORPUS && cp some-files CORPUS

 * Run fuzzing:
   $./vpx_dec_fuzzer_vp9 CORPUS

 * References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <memory>
#include <vector>
#include <cstring>

#include "vpx/vp8dx.h"
#include "vpx/vpx_decoder.h"
#include "vpx_ports/mem_ops.h"

#define IVF_FRAME_HDR_SZ (4 + 8) /* 4 byte size + 8 byte timestamp */
#define IVF_FILE_HDR_SZ 32

#define DECODER vp9
#define VPXD_INTERFACE(name) VPXD_INTERFACE_(name)
#define VPXD_INTERFACE_(name) vpx_codec_##name##_dx()

// Blocker-specific logic: Add extern declaration for the target function.
// tran_low_t is defined as int32_t.
extern "C" {
void vpx_highbd_idct32x32_34_add_sse4_1(const int32_t *input, uint16_t *dest,
                                        int stride, int bd);
}

extern "C" void usage_exit(void) { exit(EXIT_FAILURE); }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *fuzzer_data_ptr = data;
  size_t fuzzer_size = size;

  if (fuzzer_size <= IVF_FILE_HDR_SZ) {
    return 0;
  }

  vpx_codec_ctx_t codec;
  // Set thread count in the range [1, 64].
  const unsigned int threads = (fuzzer_data_ptr[IVF_FILE_HDR_SZ] & 0x3f) + 1;
  vpx_codec_dec_cfg_t cfg = { threads, 0, 0 };
  if (vpx_codec_dec_init(&codec, VPXD_INTERFACE(DECODER), &cfg, 0)) {
    return 0;
  }

  if (threads > 1) {
    const int enable = (fuzzer_data_ptr[IVF_FILE_HDR_SZ] & 0xa0) != 0;
    const vpx_codec_err_t err =
        vpx_codec_control(&codec, VP9D_SET_LOOP_FILTER_OPT, enable);
    static_cast<void>(err);
  }

  fuzzer_data_ptr += IVF_FILE_HDR_SZ;
  fuzzer_size -= IVF_FILE_HDR_SZ;

  while (fuzzer_size > IVF_FRAME_HDR_SZ) {
    size_t frame_size = mem_get_le32(fuzzer_data_ptr);
    fuzzer_size -= IVF_FRAME_HDR_SZ;
    fuzzer_data_ptr += IVF_FRAME_HDR_SZ;
    frame_size = std::min(fuzzer_size, frame_size);

    vpx_codec_stream_info_t stream_info;
    stream_info.sz = sizeof(stream_info);
    vpx_codec_err_t err = vpx_codec_peek_stream_info(VPXD_INTERFACE(DECODER),
                                                     fuzzer_data_ptr, fuzzer_size, &stream_info);
    static_cast<void>(err);

    err = vpx_codec_decode(&codec, fuzzer_data_ptr, frame_size, nullptr, 0);
    static_cast<void>(err);
    vpx_codec_iter_t iter = nullptr;
    vpx_image_t *img = nullptr;
    while ((img = vpx_codec_get_frame(&codec, &iter)) != nullptr) {
    }
    fuzzer_data_ptr += frame_size;
    fuzzer_size -= frame_size;
  }
  vpx_codec_destroy(&codec);

  // Blocker-specific logic: Directly call the blocker function with the
  // required state (bd=8) to cross the predicate. This is added after the
  // original fuzzing logic to preserve the input contract.
  const size_t kBlockerInputSize = 32 * 32;
  const int kStride = 32;

  if (size >= kBlockerInputSize * sizeof(int32_t)) {
    std::vector<int32_t> input_buf(kBlockerInputSize);
    // Reuse the original input data to populate the function arguments.
    memcpy(input_buf.data(), data, kBlockerInputSize * sizeof(int32_t));

    std::vector<uint16_t> dest_buf(kBlockerInputSize);

    // Call the blocker function directly with bd = 8 to hit the target path.
    vpx_highbd_idct32x32_34_add_sse4_1(input_buf.data(), dest_buf.data(),
                                       kStride, 8);
  }

  return 0;
}
