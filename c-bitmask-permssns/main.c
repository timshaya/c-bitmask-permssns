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
#define PERM_OWNER_EXEC  ((uint16_t)1u << 6)

#define PERM_GROUP_READ  ((uint16_t)1u << 5)
#define PERM_GROUP_WRITE ((uint16_t)1u << 4)
#define PERM_GROUP_EXEC  ((uint16_t)1u << 3)

#define PERM_OTHER_READ  ((uint16_t)1u << 2)
#define PERM_OTHER_WRITE ((uint16_t)1u << 1)
#define PERM_OTHER_EXEC  ((uint16_t)1u << 0)

/* Setters, etc */
void set_perm(uint16_t *mode, uint16_t mask){
    //For every bit that's 1 in mask, force that bit to 1 in mode:
    *mode |= mask;
    /* e.g.
        0000 0000 0000 0000 // mode = 0, in binary
        0000 0001 0000 0000 // mask = PERM_OWNER_READ or (1u << 8)
        ------------------- // perform a bitwise OR (mode | mask)
        0000 0001 0000 0000 // &mode is now "0000 0001 0000 0000" in binary
    */
}

int has_perm(uint16_t mode, uint16_t mask){
    return (mode & mask);
}

/* Print permissions as rwxr-x--- style */
void print_mode(uint16_t mode){
    char buf[10];
    
    buf[0] = has_perm(mode, PERM_OWNER_READ)  ? 'r' : '-';
    buf[1] = has_perm(mode, PERM_OWNER_WRITE) ? 'w' : '-';
    buf[2] = has_perm(mode, PERM_OWNER_EXEC)  ? 'x' : '-';
    
    buf[3] = has_perm(mode, PERM_GROUP_READ)  ? 'r' : '-';
    buf[4] = has_perm(mode, PERM_GROUP_WRITE) ? 'w' : '-';
    buf[5] = has_perm(mode, PERM_GROUP_EXEC)  ? 'x' : '-';

    buf[6] = has_perm(mode, PERM_OTHER_READ)  ? 'r' : '-';
    buf[7] = has_perm(mode, PERM_OTHER_WRITE) ? 'w' : '-';
    buf[8] = has_perm(mode, PERM_OTHER_EXEC)  ? 'x' : '-';
    buf[9] = '\0';
    
    printf("%s\n", buf);
}

int main(int argc, const char * argv[]) {
    
    uint16_t mode = 0; //0000 0000 0000 0000 in binary
    
    /* e.g. Set OWNER permissions to rwx------
        
        In binary, this is what happens set_perm(&mode, PERM_OWNER_READ | PERM_OWNER_WRITE | PERM_OWNER_EXEC) is called:
            &mode is "value of" mode, which starts as 0 or 0000 0000 0000 0000
                PERM_OWNER_READ  = 0000 0001 0000 0000
                PERM_OWNER_WRITE = 0000 0000 1000 0000
                PERM_OWNER_EXEC  = 0000 0000 0100 0000
            then
                0000 0000 0000 0000 // mode = 0
                0000 0001 0000 0000 // combine with result of PERM_OWNER_READ (1u << 8)
                ------------------- // perform a bitwise OR  (mode | mask)
                0000 0001 0000 0000 // &mode is now 0000 0001 0000 0000 in binary, also saying READ permission is 1 or "ON"
                
                0000 0001 0000 0000 // mode = 0000 0001 0000 0000
                0000 0000 1000 0000 // combine with result of PERM_OWNER_WRITE (1u << 7)
                -------------------
                0000 0001 1000 0000
     
                0000 0001 1000 0000
                0000 0000 0100 0000 // combine with result of PERM_OWNER_EXEC (1u << 6)
                -------------------
                0000 0001 1100 0000
     */
    set_perm(&mode, PERM_OWNER_READ | PERM_OWNER_WRITE | PERM_OWNER_EXEC);
    
    set_perm(&mode, PERM_GROUP_READ | PERM_GROUP_EXEC);
    
    printf("Initial value of mode:  ");
    print_mode(mode); //rwxr-x---
    printf("\n\n");
    
    return EXIT_SUCCESS;
}
