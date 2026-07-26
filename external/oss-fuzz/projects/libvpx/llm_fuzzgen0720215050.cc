#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "vpx/vpx_encoder.h"
#include "vpx/vp8cx.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vp8dx.h"
#include "vpx_ports/mem.h"
#include "vpx_scale/yv12config.h"
#include "vp8/common/onyxd.h"
#include "vp8/common/postproc.h"
#include "vp8/common/ppflags.h"
#include "vpx_mem/vpx_mem.h"

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  vpx_codec_iface_t *decoder_iface = vpx_codec_vp8_dx();
  vpx_codec_ctx_t decoder;
  if (vpx_codec_dec_init_ver(&decoder, decoder_iface, nullptr, 0, VPX_DECODER_ABI_VERSION) != VPX_CODEC_OK) {
    return 0;
  }

  if (vpx_codec_decode(&decoder, data, size, nullptr, 0) != VPX_CODEC_OK) {
    vpx_codec_destroy(&decoder);
    return 0;
  }

  vpx_codec_iter_t iter = nullptr;
  vpx_image_t *img = vpx_codec_get_frame(&decoder, &iter);
  if (img) {
    YV12_BUFFER_CONFIG frame_to_show_config;
    memset(&frame_to_show_config, 0, sizeof(frame_to_show_config));
    frame_to_show_config.y_buffer = img->planes[VPX_PLANE_Y];
    frame_to_show_config.u_buffer = img->planes[VPX_PLANE_U];
    frame_to_show_config.v_buffer = img->planes[VPX_PLANE_V];
    frame_to_show_config.y_width = img->d_w;
    frame_to_show_config.y_height = img->d_h;
    frame_to_show_config.uv_width = (img->d_w + 1) / 2;
    frame_to_show_config.uv_height = (img->d_h + 1) / 2;
    frame_to_show_config.y_stride = img->stride[VPX_PLANE_Y];
    frame_to_show_config.uv_stride = img->stride[VPX_PLANE_U];

    VP8_COMMON oci;
    memset(&oci, 0, sizeof(oci));
    oci.Width = img->d_w;
    oci.Height = img->d_h;
    oci.postproc_state.last_base_qindex = fdp.ConsumeIntegral<int>();
    oci.postproc_state.last_frame_valid = fdp.ConsumeBool();
    oci.base_qindex = fdp.ConsumeIntegral<int>();
    oci.filter_level = fdp.ConsumeIntegral<int>();
    oci.frame_to_show = &frame_to_show_config;

    vp8_ppflags_t ppflags;
    ppflags.post_proc_flag = fdp.ConsumeIntegral<int>();
    ppflags.deblocking_level = fdp.ConsumeIntegral<int>();
    ppflags.noise_level = fdp.ConsumeIntegral<int>();

    YV12_BUFFER_CONFIG dest;
    memset(&dest, 0, sizeof(dest));

    vp8_post_proc_frame(&oci, &dest, &ppflags);

    if (oci.postproc_state.generated_noise) {
      vpx_free(oci.postproc_state.generated_noise);
    }
    if (oci.post_proc_buffer_int_used) {
      vp8_yv12_de_alloc_frame_buffer(&oci.post_proc_buffer_int);
    }
  }

  vpx_codec_destroy(&decoder);

  return 0;
}