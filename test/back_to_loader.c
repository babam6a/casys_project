#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

int main(int argc, char **argv) {
    struct rusage usage_start, usage_end;

    if (getrusage(RUSAGE_SELF, &usage_start) < 0) {
        printf("rusage start error!\n");
        exit(-1);
    }

    printf("hello, world!\n");
    
    if (getrusage(RUSAGE_SELF, &usage_end) < 0) {
        printf("rusage end error!\n");
        exit(-1);
    }
    print_mem_status(&usage_start, &usage_end);
    return_to_loader();
}