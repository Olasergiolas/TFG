#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

void printRes(char str[], unsigned len){
    for (unsigned i = 0; i < len; ++i)
        printf("%02X", str[i]);
}

void processArgs(char str[]){
    unsigned len = strlen(str);
    
    if (len > 10 && str[0] == 'a'){
        str = NULL;
        printf("CRASH %c", str[0]); 
    }

    for (unsigned i = 0; i < len; ++i){
        str[i] = (char)(str[i] ^ 'c');
    }

    printRes(str, len);
}

int main(int argc, char* argv[]){
    if (argc != 2)
        exit(1);
    
    sleep(2);
    processArgs(argv[1]);
}