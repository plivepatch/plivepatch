#include <stdio.h>
#include <unistd.h>
#include "func.h"

int main()
{
    while(1){
        printf("+++\n");
        oldprint();
        printf("---\n");
        sleep(5);
    }
    return 0;
}
