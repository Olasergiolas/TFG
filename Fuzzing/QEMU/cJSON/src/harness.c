#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
#include "cJSON_Utils.h"
#include <sys/stat.h>

char* read_input(char* path){
    FILE *f;
    struct stat st;
    char* content = NULL;
    size_t read_elements = 0;

    f = fopen(path, "rb");
    if (f == NULL)
        exit(1);

    stat(path, &st);
    content = (char*)malloc(st.st_size);
    if (fread(content, st.st_size, 1, f) != 1)
        exit(1);
    
    return content;
}

int main(int argc, char** argv){
    char* res = NULL;
    char* content = NULL;

    if (argc != 2){
        printf("Usage: %s [path-to-json-file]", argv[0]);
        exit(1);
    }
    
    content = read_input(argv[1]);

    cJSON_Minify(content);
    cJSON *json = cJSON_Parse(content);
    res = cJSON_Print(json);
    printf("%s", res);
}