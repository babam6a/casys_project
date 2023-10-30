#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include "utils.h"

int main(void) {
    struct rusage usage_start, usage_end;

    if (getrusage(RUSAGE_SELF, &usage_start) < 0) {
        printf("rusage start error!\n");
        exit(-1);
    }

    char repeat[32] = "0123456789abcdefghijklmnop";
    int size = 0x100000;
    int reps = 10000;
    // struct timespec start, end;

    // clock_gettime(CLOCK_MONOTONIC, &start);
    /* repeatedly write on malloc'ed page */
    for (int i = 0; i < reps; i++) {
        char *test = (char *)malloc(size);
        char *test_pointer = test;
        for (int j = 0; j < size / 32; j++) {
            strncpy(test_pointer, repeat, 32);
            test_pointer += 32;
        }
        free(test);
    }
    if (getrusage(RUSAGE_SELF, &usage_end) < 0) {
        printf("rusage end error!\n");
        exit(-1);
    }
    print_mem_status(&usage_start, &usage_end);
}