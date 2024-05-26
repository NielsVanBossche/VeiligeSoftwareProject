#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

void* malloc(size_t size) {
    static void* (*real_malloc)(size_t) = NULL;
    if (!real_malloc) {
        real_malloc = dlsym(RTLD_NEXT, "malloc");
    }

    void* ptr = real_malloc(size);
    printf("malloc(%zu) = %p\n", size, ptr);
    return ptr;
}
