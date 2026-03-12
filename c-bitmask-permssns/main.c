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
#define PERM_OWNER_READ  ((uint16_t)(1u << 8)) //1u = 0000 0000 0000 0001, after (1u << 8) it becomes 0000 0001 0000 0000
#define PERM_OWNER_WRITE ((uint16_t)(1u << 7))
#define PERM_OWNER_EXEC  ((uint16_t)(1u << 6))

#define PERM_GROUP_READ  ((uint16_t)(1u << 5))
#define PERM_GROUP_WRITE ((uint16_t)(1u << 4))
#define PERM_GROUP_EXEC  ((uint16_t)(1u << 3))

#define PERM_OTHER_READ  ((uint16_t)(1u << 2))
#define PERM_OTHER_WRITE ((uint16_t)(1u << 1))
#define PERM_OTHER_EXEC  ((uint16_t)(1u << 0))

#define PERM_USER_MASK   (PERM_OWNER_READ | PERM_OWNER_WRITE | PERM_OWNER_EXEC)
#define PERM_GROUP_MASK  (PERM_GROUP_READ | PERM_GROUP_WRITE | PERM_GROUP_EXEC)
#define PERM_OTHER_MASK  (PERM_OTHER_READ | PERM_OTHER_WRITE | PERM_OTHER_EXEC)
#define PERM_ALL_MASK    (PERM_USER_MASK | PERM_GROUP_MASK | PERM_OTHER_MASK)

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

static void mode_to_rwx9(uint16_t mode, char out[10]) {
    
    //out[0] = has_perm(mode, PERM_OWNER_READ)  ? 'r' : '-';
    out[0] = (mode & PERM_OWNER_READ)  ? 'r' : '-';
    out[1] = (mode & PERM_OWNER_WRITE) ? 'w' : '-';
    out[2] = (mode & PERM_OWNER_EXEC)  ? 'x' : '-';
    
    out[3] = (mode & PERM_GROUP_READ)  ? 'r' : '-';
    out[4] = (mode & PERM_GROUP_WRITE) ? 'w' : '-';
    out[5] = (mode & PERM_GROUP_EXEC)  ? 'x' : '-';

    out[6] = (mode & PERM_OTHER_READ)  ? 'r' : '-';
    out[7] = (mode & PERM_OTHER_WRITE) ? 'w' : '-';
    out[8] = (mode & PERM_OTHER_EXEC)  ? 'x' : '-';
    
    out[9] = '\0';
}

static int parse_absolute_rwx9(const char *line, uint16_t *out_mode) {
    
    //collect 9 non-whitespace chars, ignoring trailing newline
    char s[10];
    int n = 0;
    
    for(const char *p = line; *p != '\0' && *p != '\n'; p++ ) {
        if(isspace((unsigned char)*p)) continue;
        if (n < 9) s[n++] = (char)tolower((unsigned char)*p);
        else return -1;
    }
    if (n != 9) return -1;
    
    //validate positions: (r|-) (w|-) (x|-) repeated 3 times
    for(int i = 0; i < 9; i++) {
        char c = s[i];
        if(c == '-') continue;
        if((i % 3 == 0 && c != 'r') ||
           (i % 3 == 1 && c != 'w') ||
           (i % 3 == 2 && c != 'x')) {
            return -1;
        }
    }
    
    uint16_t m = 0;
    if(s[0] == 'r') m |= PERM_OWNER_READ;
    if(s[1] == 'w') m |= PERM_OWNER_WRITE;
    if(s[2] == 'x') m |= PERM_OWNER_EXEC;
 
    if(s[3] == 'r') m |= PERM_GROUP_READ;
    if(s[4] == 'w') m |= PERM_GROUP_WRITE;
    if(s[5] == 'x') m |= PERM_GROUP_EXEC;

    if(s[6] == 'r') m |= PERM_OTHER_READ;
    if(s[7] == 'w') m |= PERM_OTHER_WRITE;
    if(s[8] == 'x') m |= PERM_OTHER_EXEC;

    *out_mode = m;
    return 0;
}

/*
   Supported input styles:
     - "u=rw, g=r, o=" (chmod-style, applied to current mode)
     - "g+w"           (chmod-style, applied to current mode)
     - "rwxr-x---"     (absolute mode)
 
   Returns 0 on success, -1 on invalid input
*/
static int parse_perm_line(const char *line, uint16_t current_mode, uint16_t *out_mode) {
    
    //First try absolute rwx9
    uint16_t abs_mode = 0;
    if(parse_absolute_rwx9(line, &abs_mode) == 0) {
        *out_mode = abs_mode;
        return 0;
    }
    
    // otherwise parse chdmod-style clauses: [who][op][perm] (comma-separated)
    // who: one or more of u g o a
    // op: + or =
    // perms: r w x (may be empty only for '=' like o=)
    const char *p = line;
    uint16_t mode = current_mode;
    
    // skip leading whitespace
    while(isspace((unsigned char)*p)) p++;
    if(*p == '\0' || *p == '\n') return -1;
    
    for (;;) {
        // skip separators
        while(isspace((unsigned char)*p) || *p == ',') p++;
        if(*p == '\0' || *p == '\n') break;
        
        // parse who
        unsigned who = 0; // bit0=u, bit1=g, bit2=o
        while(*p) {
            char c = (char)tolower((unsigned char)*p);
            if (c == 'u') who |= 1u;
            else if (c == 'g') who |= 2u;
            else if (c == 'o') who |= 4u;
            else if (c == 'a') who |= 7u;
            else break;
            p++;
        }
        if (who == 0) return -1; // require explicit who for this simplified spec
        
        // parse op
        char op = *p;
        if (op != '+' && op != '=') return -1;
        p++;
        
        // parse perms (rwx)
        unsigned perms = 0; // bit0=r, bit1=w, bit2=x
        while(*p) {
            char c = (char)tolower((unsigned char)*p);
            if (c == 'r') perms |= 1u;
            else if (c == 'w') perms |= 2u;
            else if (c == 'x') perms |= 4u;
            else break;
            p++;
        }
        
        // Only '=' may have empty perms (e.g. o=)
        if (op != '=' && perms == 0) return -1;
        
        //Build affected mask for '=' (clears those classes first )
        uint16_t affected = 0;
        if (who & 1u) affected |= PERM_USER_MASK;
        if (who & 2u) affected |= PERM_GROUP_MASK;
        if (who & 4u) affected |= PERM_OTHER_MASK;

        // Build bits to add/set
        uint16_t bits = 0;
        if (perms & 1u) { //r
            if (who & 1u) bits |= PERM_OWNER_READ;
            if (who & 2u) bits |= PERM_GROUP_READ;
            if (who & 4u) bits |= PERM_OTHER_READ;
        }
        if (perms & 2u) { //w
            if (who & 1u) bits |= PERM_OWNER_WRITE;
            if (who & 2u) bits |= PERM_GROUP_WRITE;
            if (who & 4u) bits |= PERM_OTHER_WRITE;
        }
        if (perms & 4u) { //x
            if (who & 1u) bits |= PERM_OWNER_EXEC;
            if (who & 2u) bits |= PERM_GROUP_EXEC;
            if (who & 4u) bits |= PERM_OTHER_EXEC;
        }
        
        // Apply op
        if (op == '+') {
            mode |= bits;
        } else { // '='
            mode = (uint16_t)(mode & (uint16_t)~affected);
            mode |= bits;
        }
    }
    
    *out_mode = (uint16_t)(mode & PERM_ALL_MASK);
    return 0;
}

int main(void) {
    
    char buffer[256];  //input container
    uint16_t mode = 0; //0000 0000 0000 0000 in binary
    
    puts("Allowed inputs:");
    puts("   u=rw,g=r,o=");
    puts("   g+w");
    puts("   rwxr-x---");
    puts("Type  q to quit.\n");
    
    while(1) {
        fputs("> ", stdout);
        
        if(!fgets(buffer, sizeof buffer, stdin)) break; // EOF / error
        if(buffer[0] == 'q' || buffer[0] =='Q') break; //quit
        if(buffer[0] == 'c' || buffer[0] =='C') {
            clear_perm(&mode, PERM_ALL_MASK); //clear the values
            
        }
        
        uint16_t newMode = 0;
        if(parse_perm_line(buffer, mode, &newMode) != 0) {
            fputs("Invalid input (supported: u=rw,g=r,o= | g+w | rwxr-x---)\n", stderr);
            continue;
        }
        
        mode = newMode;
        
        //sample input:
        // o=x    ,leads to output: (--------x)
        // g=rwx  ,leads to output: (---rwx--x) (including, the previous input of o=x
        // u+r,   ,leads to output: (r--rwx--x) (including, the previous input of o=x and g=rwx
        char rwx[10];
        mode_to_rwx9(mode, rwx);
        printf("Parsed mask: 0x%04" PRIx16 " (%s)\n", mode, rwx);
    
        //to replace permissions, just enter other values like so:
        //u=r,g=,o=rx
        //so, if first time you entered g=rwx and got (---rwx---)
        //then entering "u=r,g=,o=rx" will give you (r-----r-x)        
    }
    
    return EXIT_SUCCESS;
}
