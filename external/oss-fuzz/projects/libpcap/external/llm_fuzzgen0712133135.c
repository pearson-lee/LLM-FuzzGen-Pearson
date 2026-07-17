#include "/src/libpcap/pcap/pcap.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

// Helper to remove a directory and its contents (C version)
static void RemoveDir(const char* path) {
    DIR* dir = opendir(path);
    if (!dir) {
        return;
    }

    struct dirent* entry;
    char entry_path[1024];
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        snprintf(entry_path, sizeof(entry_path), "%s/%s", path, entry->d_name);
        
        // Use lstat to handle symlinks properly and avoid infinite loops
        struct stat st;
        if (lstat(entry_path, &st) == -1) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            RemoveDir(entry_path);
        } else {
            unlink(entry_path);
        }
    }
    closedir(dir);
    rmdir(path);
}

// Helper to consume a block of bytes from the fuzzing input
static size_t consume_bytes(const uint8_t** data, size_t* size, void* out, size_t out_size) {
    if (*size < out_size) {
        return 0;
    }
    memcpy(out, *data, out_size);
    *data += out_size;
    *size -= out_size;
    return out_size;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const uint8_t* p_data = data;
    size_t p_size = size;
    char errbuf[PCAP_ERRBUF_SIZE];

    uint8_t flag;

    /* Block 1: Test pcap_findalldevs_ex with file source */
    if (consume_bytes(&p_data, &p_size, &flag, sizeof(flag)) && (flag % 2)) {
        char dir_path[256];
        snprintf(dir_path, sizeof(dir_path), "/tmp/%s_dir.tmp", _FUZZ_TARGET_NAME);
        mkdir(dir_path, 0755);

        uint8_t num_files_raw;
        if (!consume_bytes(&p_data, &p_size, &num_files_raw, sizeof(num_files_raw))) {
            num_files_raw = 1;
        }
        int num_files = 1 + (num_files_raw % 5);

        for (int i = 0; i < num_files; ++i) {
            char file_path[512];
            snprintf(file_path, sizeof(file_path), "%s/file%d.pcap", dir_path, i);
            FILE* f = fopen(file_path, "wb");
            if (!f) continue;

            uint16_t content_len_raw;
            if (!consume_bytes(&p_data, &p_size, &content_len_raw, sizeof(content_len_raw))) {
                content_len_raw = 0;
            }
            size_t content_len = content_len_raw % 1024;
            if (content_len > p_size) content_len = p_size;
            
            if (content_len > 0) {
                fwrite(p_data, 1, content_len, f);
                p_data += content_len;
                p_size -= content_len;
            }
            fclose(f);
        }

        pcap_if_t *alldevs;
        char source[512];
        snprintf(source, sizeof(source), "file://%s/", dir_path);
        if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == 0) {
            pcap_freealldevs(alldevs);
        }

        RemoveDir(dir_path);
    }

    /* Block 2: Test pcap_getnonblock and pcap_compile */
    if (consume_bytes(&p_data, &p_size, &flag, sizeof(flag)) && (flag % 2)) {
        char file_path[256];
        snprintf(file_path, sizeof(file_path), "/tmp/%s_offline.pcap", _FUZZ_TARGET_NAME);
        FILE* f = fopen(file_path, "wb");
        if (f) {
            uint16_t content_len_raw;
            if (!consume_bytes(&p_data, &p_size, &content_len_raw, sizeof(content_len_raw))) {
                content_len_raw = 0;
            }
            size_t content_len = content_len_raw % 2048;
            if (content_len > p_size) content_len = p_size;
            
            if (content_len > 0) {
                fwrite(p_data, 1, content_len, f);
                p_data += content_len;
                p_size -= content_len;
            }
            fclose(f);

            pcap_t *p = pcap_open_offline(file_path, errbuf);
            if (p) {
                pcap_getnonblock(p, errbuf);

                struct bpf_program fp;
                uint8_t filter_len;
                if (!consume_bytes(&p_data, &p_size, &filter_len, sizeof(filter_len))) {
                    filter_len = 0;
                }
                if (filter_len > p_size) filter_len = p_size;

                char* filter = (char*)malloc(filter_len + 1);
                if (filter) {
                    memcpy(filter, p_data, filter_len);
                    filter[filter_len] = '\0';
                    p_data += filter_len;
                    p_size -= filter_len;

                    if (pcap_compile(p, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
                        pcap_setfilter(p, &fp);
                        pcap_freecode(&fp);
                    }
                    free(filter);
                }
                pcap_close(p);
            }
            unlink(file_path);
        }
    }

    /* Block 3: Test pcap_set_tstamp_type */
    if (consume_bytes(&p_data, &p_size, &flag, sizeof(flag)) && (flag % 2)) {
        pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
        if (p) {
            int n_tstamp_types;
            int *tstamp_types = NULL;

            n_tstamp_types = pcap_list_tstamp_types(p, &tstamp_types);
            if (n_tstamp_types >= 0) {
                int tstamp_type_val;
                if (!consume_bytes(&p_data, &p_size, &tstamp_type_val, sizeof(tstamp_type_val))) {
                    tstamp_type_val = 0;
                }
                pcap_set_tstamp_type(p, tstamp_type_val);
                
                if (n_tstamp_types > 0 && tstamp_types != NULL) {
                    pcap_free_tstamp_types(tstamp_types);
                }
            }
            pcap_close(p);
        }
    }

    return 0;
}