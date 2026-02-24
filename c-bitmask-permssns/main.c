//
//  main.c
//  c-bitmask-permssns
//
//  Created by g t2 on 2/20/26.
//
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>

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

char *endptr;

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

void clear_perm(uint16_t *mode, uint16_t mask){
    *mode &= ~mask;
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

static int parse_owner_perm(const char *line, uint16_t *out_mask) {
    
    //TODO:
    
    return 0;
}


/* statis version, initial take */
int main(void) {
    
    char buffer[256];  //input container
    uint16_t mode = 0; //0000 0000 0000 0000 in binary

//    set_perm(&mode, PERM_OWNER_READ | PERM_OWNER_WRITE | PERM_OWNER_EXEC);
//    set_perm(&mode, PERM_GROUP_READ | PERM_GROUP_EXEC);


    for(;;){
        fputs("Enter owner permissions (r/w/x e.g. rwx)  numeric mask (0400, 0x0100, 256). q to quit:\n", stdout);
        
        if(!fgets(buffer, sizeof buffer, stdin)){
            //EOF (Cmd / Ctrl D) or input error
            break;
        }
        
        if(buffer[0] =='q' || buffer[0] == 'Q'){ break;}
        
        uint16_t maskFromUsrInput = 0;
        
        //TODO: write out parse_owner_perm()
//        if(parse_owner_perm(buffer, &maskFromUsrInput != 0)){
//            fputs("Invalid input. Examples: r, rw, rwx, 0400, 0x0100, 256");
//        }
//        
        
        printf("Parked mask: 0x%04" PRIx16 " (%" PRIu16 ")\n", maskFromUsrInput, maskFromUsrInput);
        
        set_perm(&mode, maskFromUsrInput);
        
        printf("2nd value of mode:  ");
        print_mode(mode); //rwxr-x--x
        printf("\n");
    
    }
    
    return EXIT_SUCCESS;
}
