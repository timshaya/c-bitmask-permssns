//
//  main.c
//  c-bitmask-permssns
//
//  Created by g t2 on 2/20/26.
//
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


/* Bit positions (owner / group / other: r, w, x) */
#define PERM_OWNER_READ  ((uint16_t)1u << 8) //1u = 0000 0000 0000 0001, after (1u << 8) it becomes 0000 0001 0000 0000
#define PERM_OWNER_WRITE ((uint16_t)1u << 7)
#define PERM_OWNER_EXEX  ((uint16_t)1u << 6)


int main(int argc, const char * argv[]) {
    // insert code here...
    printf("Hello, bitmask permissions!\n");
    
    return EXIT_SUCCESS;
}
