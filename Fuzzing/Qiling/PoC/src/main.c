#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

void printRes(char str[], unsigned len){
    printf("Ciphered output: ");
    for (unsigned i = 0; i < len; ++i)
        printf("\\x%02X", str[i]);
    printf("\n");
}

void processArgs(char str[]){
    unsigned len = strlen(str);
    
    if (len > 10 && str[0] == 'a'){
        printf("CRASH");
        char dst[2];
        dst[6] = str[0];
    }

    for (unsigned i = 0; i < len; ++i){
        str[i] = (char)(str[i] ^ 'c');
    }

    printRes(str, len);
}

int main(int argc, char* argv[]){
    if (argc != 2){
        printf("Usage: %s <input_string>\n", argv[0]);
        exit(1);
    }
    
    sleep(5);
    processArgs(argv[1]);
}