#include <stdio.h>
#include <string.h>
inline __attribute__((always_inline)) void no_codex_func(){
    if (strcmp(flag, E("CTF{i_am_haxxor}")) == 0)
        puts("the flag is correct");
    else
        puts("incorrect flag");
}

inline __attribute__((always_inline)) void codex_func(){
    puts(E("incorrect flag"));
}
