#include <stdio.h>
#include <stdlib.h>
int isLittleEndian(){
    int num; 
    char *ptr; 
    num = 1; 
    ptr = (char *) &num;
    return (*ptr);
}

int main(int argc, char* argv[]){
    printf("Is little endian? %d\n", isLittleEndian());     
    return 0; 
}
