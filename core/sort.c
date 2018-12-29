#include "sort.h"
#include "mem.h"
#include <alloca.h>

typedef int (*cmpfun)(const void *, const void *);

// A function to implement bubble sort
void sort(void *arr, size_t num, size_t elem_size, cmpfun cmp) {
    for (size_t i = num - 1; i > 0; i--) {
        for (size_t j = 0; j < i; j++) {
            void *e1 = arr + j * elem_size;
            void *e2 = arr + (j + 1) * elem_size; // e1+1 element

            if (cmp(e1, e2) > 0) {
                void *temp = alloca(elem_size);
                memcpy(temp, e1, elem_size);
                memcpy(e1, e2, elem_size);
                memcpy(e2, temp, elem_size);
            }
        }
    }
}
