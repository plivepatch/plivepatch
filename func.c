#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include "func.h"

int oldprint(){
	printf("%ld : old original func.\n",time(0));
	return 0;
}
