#include <stdio.h>
#include <unistd.h>
#include <signal.h>

void return_to_loader() {
    kill(getpid(), SIGUSR1);
}

int main() {
    printf("hello, world!\n");
    return_to_loader();
}