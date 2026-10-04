#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

/*
 * Verification Program for lcms_cmsIT8GetData_2865
 *
 * Ground Truth: Input Dependent (Rule 1 & Rule 2)
 * Target Branch: cmsIT8GetData (cmscgats.c:2865)
 * Blocked Side: cmscgats.c:2869 (iSet = LocatePatch(it8, cPatch);)
 *
 * This program constructs a 260-byte input payload demonstrating that
 * the blocked branch at line 2869 is reachable under the original
 * fuzz target logic without any modifications to the fuzz target code.
 *
 * Compile command:
 *   gcc -Iexternal/oss-fuzz/build/out/lcms/source_code/include verify_poc.c \
 *       external/oss-fuzz/build/out/lcms/src/lcms/src/.libs/liblcms2.a -lm -o verify_poc
 */

int main() {
    char buf[1024];
    memset(buf, 0, sizeof(buf));

    // Construct valid IT8 table defining column "MYCOL"
    int n = sprintf(buf,
        "LCMS/TESTING\n"
        "NUMBER_OF_SETS 2\n"
        "NUMBER_OF_FIELDS 2\n"
        "BEGIN_DATA_FORMAT\n"
        " SAMPLE_ID MYCOL\n"
        "END_DATA_FORMAT\n"
        "BEGIN_DATA\n"
        " P0 10\n"
        " P1 20\n"
        "END_DATA\n"
        "# "
    );

    // Pad with comment '-' characters up to offset 252
    while (n < 252) {
        buf[n++] = '-';
    }
    // Newline at 252, then start a new comment line "# " at 253..254
    buf[252] = '\n';
    buf[253] = '#';
    buf[254] = ' ';

    // At offset 255..259, place the exact column token "MYCOL"
    buf[255] = 'M';
    buf[256] = 'Y';
    buf[257] = 'C';
    buf[258] = 'O';
    buf[259] = 'L';
    size_t total_size = 260;

    printf("[+] Input payload constructed. Total size: %zu bytes.\n", total_size);

    // 1. Target executes cmsIT8LoadFromMem(context, data, size)
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHANDLE hIT8 = cmsIT8LoadFromMem(context, buf, total_size);
    if (!hIT8) {
        printf("[-] cmsIT8LoadFromMem failed!\n");
        return 1;
    }
    printf("[+] cmsIT8LoadFromMem succeeded! hIT8 = %p\n", (void*)hIT8);

    // 2. Target executes its string slicing logic
    char str1[256];
    char str2[256];
    char str3[256];
    size_t offset = 0;

    if (total_size > offset) {
        size_t len = total_size - offset > 255 ? 255 : total_size - offset;
        memcpy(str1, buf + offset, len);
        str1[len] = '\0';
        offset += len;
    } else {
        str1[0] = '\0';
    }

    if (total_size > offset) {
        size_t len = total_size - offset > 255 ? 255 : total_size - offset;
        memcpy(str2, buf + offset, len);
        str2[len] = '\0';
        offset += len;
    } else {
        str2[0] = '\0';
    }

    if (total_size > offset) {
        size_t len = total_size - offset > 255 ? 255 : total_size - offset;
        memcpy(str3, buf + offset, len);
        str3[len] = '\0';
        offset += len;
    } else {
        str3[0] = '\0';
    }

    printf("[+] Sliced str1 (first 20 chars): '%.20s...'\n", str1);
    printf("[+] Sliced str2: '%s'\n", str2);

    // 3. Target executes line 66: cmsIT8SetTableByLabel
    cmsIT8SetTableByLabel(hIT8, str1, str2, str3);

    // 4. Target executes line 75: cmsIT8GetData(hIT8, str1, str2)
    // Inside cmsIT8GetData (cmscgats.c:2857):
    //   iField = LocateSample(it8, str2);
    //   if (iField < 0) return NULL;         <-- LINE 2865
    //   iSet = LocatePatch(it8, str1);        <-- LINE 2869 (BLOCKED SIDE REACHED!)
    int field_index = cmsIT8FindDataFormat(hIT8, str2);
    printf("[+] LocateSample(it8, str2) = %d\n", field_index);

    if (field_index >= 0) {
        printf("[SUCCESS] iField >= 0! Condition (iField < 0) evaluated to FALSE!\n");
        printf("[SUCCESS] Reached Line 2869 (iSet = LocatePatch(it8, cPatch))!\n");
    } else {
        printf("[-] Failed: iField < 0.\n");
        return 1;
    }

    const char *val = cmsIT8GetData(hIT8, str1, str2);
    printf("[+] cmsIT8GetData returned: %p\n", (void*)val);

    cmsIT8Free(hIT8);
    cmsDeleteContext(context);
    return 0;
}
