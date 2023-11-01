#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "utils.h"

int size = 100000 * (1<<12);
char page[100000 * (1<<12)];

int main(void) {
    struct rusage usage_start, usage_end;

    if (getrusage(RUSAGE_SELF, &usage_start) < 0) {
        printf("rusage start error!\n");
        exit(-1);
    }

    char repeat[32] = "0123456789abcdefghijklmnop";
    int reps = 1;

    /* repeatedly write on malloc'ed page */
    for (int i = 0; i < reps; i++) {
        memset(page, 0, size);
        char *curr_page = page;
        for (int j = 0; j < size / 32; j++) {
            strncpy(curr_page, repeat, 32);
            curr_page += 32;
        }
    }
    if (getrusage(RUSAGE_SELF, &usage_end) < 0) {
        printf("rusage end error!\n");
        exit(-1);
    }
    print_mem_status(&usage_start, &usage_end);
    return_to_loader();
}