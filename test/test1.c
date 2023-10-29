#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int size = 100000 * (1<<12);
char page[100000 * (1<<12)];

double get_spent_time(struct timespec start, struct timespec end) {
    double sec = (end.tv_sec - start.tv_sec) * 1000000000;
    double ns = end.tv_nsec - start.tv_nsec;

    return sec + ns;
}

void get_mem_usage() {
    FILE *status = fopen("/proc/self/status", "r");
    char buf[0x1000];

    fread(buf, 1, sizeof(buf), status);

    char *mem = strstr(buf, "VmSize");
    char *cut = strstr(mem, "\n");
    cut[0] = '\0';

    printf("%s\n, mem");
}

int main(void) {
    char repeat[32] = "0123456789abcdefghijklmnop";
    int reps = 1;
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    /* repeatedly write on malloc'ed page */
    for (int i = 0; i < reps; i++) {
        memset(page, 0, size);
        char *curr_page = page;
        for (int j = 0; j < size / 32; j++) {
            strncpy(curr_page, repeat, 32);
            curr_page += 32;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_spent = get_spent_time(start, end) / reps;

    printf("[avg_time]: %.1f ns\n", time_spent);
    //get_mem_usage();
}