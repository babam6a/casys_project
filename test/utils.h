#include <sys/resource.h>

void print_mem_status(struct rusage *usage_start, struct rusage *usage_end);
void return_to_loader(void);