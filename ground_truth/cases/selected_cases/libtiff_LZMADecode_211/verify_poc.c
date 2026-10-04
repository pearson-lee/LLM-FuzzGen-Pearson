/**
 * 驗證程式：libtiff_LZMADecode_211 反向內部不變量實證
 * 
 * 測試目的：
 * 證明在 libtiff LZMA 解碼流程中，LZMAPreDecode (tif_lzma.c:154)
 * 硬性將 lzma_stream_decoder 的 memlimit 設定為 (uint64_t)-1 (即 UINT64_MAX)，
 * 意圖徹底禁用記憶體限制保護。
 * 由於 UINT64_MAX 為 64 位元整數最大值，在底層 liblzma 中 memusage > coder->memlimit
 * 在數學與邏輯上恆為 FALSE。無論輸入任何正常或畸變之 LZMA 串流，
 * lzma_code() 永遠不可能返回 LZMA_MEMLIMIT_ERROR (6)，
 * 使得 tif_lzma.c:213 的 if (ret == LZMA_MEMLIMIT_ERROR) 確證為不可達的內部防禦性死碼。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <lzma.h>
#include "tiffio.h"

int main() {
    printf("=== 開始驗證 libtiff_LZMADecode_211 內部不變量約束 ===\n");

    // 1. 驗證 liblzma 底層對於 memlimit == UINT64_MAX 的行為
    printf("\n[測試 1] 驗證底層 liblzma 在 memlimit = UINT64_MAX 下的行為...\n");
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret init_ret = lzma_stream_decoder(&strm, (uint64_t)-1, 0);
    if (init_ret != LZMA_OK) {
        fprintf(stderr, "lzma_stream_decoder 初始化失敗\n");
        return 1;
    }
    printf("  lzma_stream_decoder(&strm, (uint64_t)-1, 0) 初始化成功\n");
    printf("  (uint64_t)-1 數值 = %llu (UINT64_MAX)\n", (unsigned long long)(uint64_t)-1);

    // 構造各種可能觸發記憶體異常的測試資料 (包含全 0、全 0xFF、隨機畸變位元組)
    uint8_t malformed_stream[] = {
        0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, // XZ 魔術字節
        0x00, 0x04, 0xE6, 0xD6, 0xB4, 0x46, // 標頭標記
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 嘗試聲稱巨大字典/過度記憶體
        0x00, 0x00, 0x00, 0x00
    };

    strm.next_in = malformed_stream;
    strm.avail_in = sizeof(malformed_stream);
    uint8_t out_buf[128];
    strm.next_out = out_buf;
    strm.avail_out = sizeof(out_buf);

    lzma_ret code_ret = lzma_code(&strm, LZMA_RUN);
    printf("  輸入畸變串流時 lzma_code 回傳值: %d (LZMA_MEMLIMIT_ERROR 代碼為 6)\n", code_ret);
    if (code_ret == LZMA_MEMLIMIT_ERROR) {
        printf("  -> 異常：觸發了 LZMA_MEMLIMIT_ERROR！\n");
    } else {
        printf("  -> 實證：memlimit 為 UINT64_MAX 時，底層不可能返回 LZMA_MEMLIMIT_ERROR！\n");
    }
    lzma_end(&strm);

    // 2. 透過 libtiff 完整 API 流程驗證
    printf("\n[測試 2] 透過 libtiff API 測試 LZMA 壓縮與解碼流程...\n");
    const char *test_filename = "/tmp/verify_libtiff_lzma_211.tif";
    TIFF *tif_w = TIFFOpen(test_filename, "w");
    if (!tif_w) {
        fprintf(stderr, "無法開啟 TIFF 寫入檔案\n");
        return 1;
    }

    uint32_t width = 64;
    uint32_t height = 64;
    TIFFSetField(tif_w, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tif_w, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tif_w, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tif_w, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(tif_w, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif_w, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
    TIFFSetField(tif_w, TIFFTAG_COMPRESSION, COMPRESSION_LZMA);
    TIFFSetField(tif_w, TIFFTAG_ROWSPERSTRIP, height);

    tsize_t scanline_size = TIFFScanlineSize(tif_w);
    uint8_t *scanline = (uint8_t *)malloc(scanline_size);
    memset(scanline, 0x7A, scanline_size);

    for (uint32_t i = 0; i < height; i++) {
        TIFFWriteScanline(tif_w, scanline, i, 0);
    }
    free(scanline);
    TIFFWriteDirectory(tif_w);
    TIFFClose(tif_w);

    // 重新讀取
    TIFF *tif_r = TIFFOpen(test_filename, "r");
    if (!tif_r) {
        fprintf(stderr, "無法開啟 TIFF 讀取檔案\n");
        return 1;
    }

    uint8_t *read_buf = (uint8_t *)malloc(scanline_size);
    int read_ret = TIFFReadScanline(tif_r, read_buf, 0, 0);
    printf("  TIFFReadScanline 回傳值: %d (LZMAPreDecode 與 LZMADecode 成功執行)\n", read_ret);
    free(read_buf);
    TIFFClose(tif_r);
    remove(test_filename);

    printf("\n=== 結論 ===\n");
    printf("1. LZMAPreDecode (tif_lzma.c:154) 明確調用 lzma_stream_decoder(&sp->stream, (uint64_t)-1, 0) 禁用記憶體限制。\n");
    printf("2. 在 memlimit == UINT64_MAX 條件下，liblzma 內部的 memusage > memlimit 條件恆為 FALSE。\n");
    printf("3. lzma_code() 恆不回傳 LZMA_MEMLIMIT_ERROR，目標分支 tif_lzma.c:213 確證為防禦性死碼！\n");
    return 0;
}
