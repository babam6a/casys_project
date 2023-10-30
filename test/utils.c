#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include "utils.h"

void print_mem_status(struct rusage *usage_start, struct rusage *usage_end) {
        long utime_s, utime_us, stime_s, stime_us, ttime_s, ttime_us;

        utime_s = (usage_end->ru_utime.tv_sec - usage_start->ru_utime.tv_sec) * 1000000;
        utime_us = usage_end->ru_utime.tv_usec - usage_start->ru_utime.tv_usec;

        stime_s = (usage_end->ru_stime.tv_sec - usage_start->ru_stime.tv_sec) * 1000000;
        stime_us = usage_end->ru_stime.tv_usec - usage_start->ru_stime.tv_usec;


        ttime_s = utime_s + stime_s;
        ttime_us = utime_us + stime_us;

        if (ttime_us >= 1000000) {
        ++ttime_s;
        ttime_us -= 1000000;
        }

        printf("----------------------------------------------------------------\n");   
        printf("########## This is information from getrusage() ##########\n");
        printf("Info | before | after | differnece \n");
        printf("----------------------------------------------------------------\n");
        printf( "utime | %ld.%06ld | %ld.%06ld | %ld.%06ld\n", 
                usage_start->ru_utime.tv_sec, usage_start->ru_utime.tv_usec,
                usage_end->ru_utime.tv_sec, usage_end->ru_utime.tv_usec,
                utime_s, utime_us);  

        printf( "stime | %ld.%06ld | %ld.%06ld | %ld.%06ld\n", 
                usage_start->ru_stime.tv_sec, usage_start->ru_stime.tv_usec,
                usage_end->ru_stime.tv_sec, usage_end->ru_stime.tv_usec,
                stime_s, stime_us);

        printf( "ttime | %ld.%06ld | %ld.%06ld | %ld.%06ld\n", 
                ttime_s, ttime_us, ttime_s, ttime_us, ttime_s, ttime_us );  

        printf( "maxrss | %ld | %ld | %ld\n",  usage_start->ru_maxrss,
                usage_end->ru_maxrss, usage_end->ru_maxrss - usage_start->ru_maxrss);
                
        printf( "minflt | %ld | %ld | %ld\n",  usage_start->ru_minflt,
                usage_end->ru_minflt, usage_end->ru_minflt - usage_start->ru_minflt);

        printf( "majflt | %ld | %ld | %ld\n",  usage_start->ru_majflt,
                usage_end->ru_majflt, usage_end->ru_majflt - usage_start->ru_majflt);  

        printf( "nvcsw | %ld | %ld | %ld\n",  usage_start->ru_nvcsw,
                usage_end->ru_nvcsw, usage_end->ru_nvcsw - usage_start->ru_nvcsw);  

        printf( "nivcsw | %ld | %ld | %ld\n",  usage_start->ru_nivcsw,
                usage_end->ru_nivcsw, usage_end->ru_nivcsw - usage_start->ru_nivcsw);
        printf("----------------------------------------------------------------\n");
}