#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
#include "cJSON_Utils.h"
#include <sys/stat.h>
#include <string.h>

char* read_input(char* path){
    FILE *f;
    struct stat st;
    char* content = NULL;
    size_t read_elements = 0;

    f = fopen(path, "rb");
    if (f == NULL)
        exit(1);

    stat(path, &st);
    if (st.st_size == 0)
        exit(1);

    content = (char*)malloc(st.st_size + 1);
    content[st.st_size] = '\0';                                                 // Avoid heap-buffer-overflow in strlen with non null terminated strings
    if (fread(content, st.st_size, 1, f) != 1)
        exit(1);
    
    return content;
}

int main(int argc, char** argv){
    char* print = NULL;
    char* print_buf = NULL;
    char* print_buf_fmt = NULL;
    char* content = NULL;
    char* content_min = NULL;
    size_t content_size = 0;

    if (argc < 2 || argc > 3){
        printf("Usage: %s [path-to-json-file]", argv[0]);
        exit(1);
    }
    
    content = read_input(argv[1]);
    content_size = strlen(content);

    content_min = (char*)malloc(strlen(content) + 1);
    memcpy(content_min, content, content_size);
    cJSON_Minify(content_min);

    cJSON *json = cJSON_Parse(content);

    print = cJSON_Print(json);
    print_buf = cJSON_PrintBuffered(json, 1, 0);
    print_buf_fmt = cJSON_PrintBuffered(json, 1, 1);

    if (argc == 3 && strcmp(argv[2], "-v") == 0){
        printf("cJSON_Print method:\n%s\n", print);
        printf("cJSON_PrintBuffered method:\n%s\n", print_buf);
        printf("cJSON_PrintBuffered fmt method:\n%s\n", print_buf_fmt);
    }
}