#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <sys/ioctl.h>
#include "junk.h"
#include "utils.h"
#include "codex.h"

__attribute__((section(".datasec"))) uint64_t ran = 0;
__attribute__((section(".datasec"))) uint64_t saved_seed_state = 0;
uint64_t seed_state = 0;
__attribute__((section(".datasec"))) uint64_t keys[1024] = {0};

#define mark(x) __asm__ volatile (".global " x "\n " x ":\n")

extern void* fns[];
extern void* eb40;
extern void* eb40_flag;
extern void* eb40_fakeflag;
extern void* flag_begin;
extern void* flag_end;
extern void* sabotage;

void* end_sec_addr;
char bp[255];
char flag[255] = {0};
pid_t main_pid;
int runno = 0;

inline __attribute__((always_inline)) void encrypt(int i, int key, uint64_t seed_state){
    keys[key] = rand64();
    rc4(fns[i], fns[i + 1] - fns[i], (uint8_t*)&keys[key], sizeof(uint64_t));
    rc4(fns[i], fns[i + 1] - fns[i], (uint8_t*)&seed_state, sizeof(uint64_t));
}

inline __attribute__((always_inline)) void decrypt(int i, int key, uint64_t seed_state){
    rc4(fns[i], fns[i + 1] - fns[i], (uint8_t*)&seed_state, sizeof(uint64_t));
    rc4(fns[i], fns[i + 1] - fns[i], (uint8_t*)&keys[key], sizeof(uint64_t));
}

void memsetjmp(unsigned char* dst, unsigned char data, size_t len, void* jmpdst, uint64_t rdi){
    memset(dst, data, len);
    register uint64_t rdi_val asm("rdi") = rdi; \
    asm volatile ("jmp *%0":: "r"(jmpdst), "r"(rdi_val) : "memory"); \
}

inline __attribute__((always_inline)) void dosabotage(){
    //puts(E("CODEX DETECTED!!!"));
    memset(&eb40, 0x90, 2);
    ((unsigned char*)&eb40_flag)[0] ^= 0xeb ^ 0x90;
    ((unsigned char*)&eb40_flag)[1] ^= 0x20 ^ 0x90;
    ((unsigned char*)&eb40_fakeflag)[0] ^= 0xeb ^ 0x90;
    ((unsigned char*)&eb40_fakeflag)[1] ^= 0x20 ^ 0x90;
    memset(&flag_begin, 0x90, (uint64_t)&flag_end - (uint64_t)&flag_begin);
}

#include "chal.h"

#define SEC_NORMAL(junk, junk2, i, next, next_key, prev, prev_key, next_mod) \
    __attribute__((section(".mysec2,\"awx\",@progbits#"))) \
    __attribute__((force_align_arg_pointer)) \
    void section_ ## i(uint64_t old_seed_state){ \
        if (prev != -1 && prev != 0) encrypt(prev, prev_key, old_seed_state); \
        old_seed_state = seed_state; \
        seed_state = junk(seed_state); \
        seed_state = junk2(seed_state); \
        if (next) { \
            for (int j = 0; j<N_SEC; j++) { \
                if (j == i) continue; \
                if (j % MOD_VAL != next_mod) continue; \
                if(fork()==0) { \
                    alarm(3); \
                    decrypt(j, next_key, seed_state); \
                    register uint64_t rdi_val asm("rdi") = old_seed_state; \
                    asm volatile ("jmp *%0":: "r"(fns[j]), "r"(rdi_val) : "memory"); \
                } \
            } \
            if (i == 0) sleep(60); \
            _exit(0); \
        } else { \
            register uint64_t rdi_val asm("rdi") = old_seed_state; \
            asm volatile ("jmp *%0":: "r"(end_sec_addr), "r"(rdi_val) : "memory"); \
        } \
    }

#define SEC_REWRITE(i, next, next_key, prev, prev_key, next_mod, curr_key) \
    __attribute__((section(".mysec2,\"awx\",@progbits#"))) \
    __attribute__((force_align_arg_pointer)) \
    void section_ ## i(uint64_t old_seed_state){ \
        if (prev != -1 && prev != 0) encrypt(prev, prev_key, old_seed_state); \
        push_binary(bp, ".mysec2", ".datasec", fns[i], fns[i + 1], keys[curr_key], seed_state); \
        old_seed_state = seed_state; \
        if (runno == 1) { \
            kill(main_pid, SIGTERM); \
            _exit(0); \
        } \
        if (next) { \
            for (int j = 0; j<N_SEC; j++) { \
                if (j == i) continue; \
                if (j % MOD_VAL != next_mod) continue; \
                if(fork()==0) { \
                    alarm(3); \
                    decrypt(j, next_key, seed_state); \
                    register uint64_t rdi_val asm("rdi") = old_seed_state; \
                    asm volatile ("jmp *%0":: "r"(fns[j]), "r"(rdi_val) : "memory"); \
                } \
            } \
            if (i == 0) sleep(60); \
            _exit(0); \
        } else { \
            register uint64_t rdi_val asm("rdi") = old_seed_state; \
            asm volatile ("jmp *%0":: "r"(end_sec_addr), "r"(rdi_val) : "memory"); \
        } \
    }

#define SEC_SABOTAGE(i, next, next_key, prev, prev_key) \
    __attribute__((section(".mysec2,\"awx\",@progbits#"))) \
    __attribute__((force_align_arg_pointer)) \
    void section_ ## i(uint64_t old_seed_state){ \
        if (prev != -1 && prev != 0) encrypt(prev, prev_key, old_seed_state); \
        old_seed_state = seed_state; \
        if (fns[next] != end_sec_addr) decrypt(next, next_key, seed_state); \
        mark("eb40"); \
        __asm__ __volatile__(".byte 0xeb, 0x20"); \
        { \
            register uint64_t rdi_val asm("rdi") = old_seed_state; \
            asm volatile ("jmp *%0":: "r"(fns[next]), "r"(rdi_val) : "memory"); \
        } \
        __asm__ __volatile__(".fill 0x20, 1, 0x90"); \
        mark("sabotage"); \
        if (runno == 0) { \
            if (isCodex()) { \
                dosabotage(); \
                memsetjmp((unsigned char*)&sabotage, 0x90, (uint64_t)fns[i + 1] - (uint64_t)&sabotage, (void*)fns[next], old_seed_state); \
            } else { \
                register uint64_t rdi_val asm("rdi") = old_seed_state; \
                asm volatile ("jmp *%0":: "r"(fns[next]), "r"(rdi_val) : "memory"); \
            } \
        } else { \
            register uint64_t rdi_val asm("rdi") = old_seed_state; \
            asm volatile ("jmp *%0":: "r"(fns[next]), "r"(rdi_val) : "memory"); \
        } \
    } \

#define SEC_REAL_FLAG(i, next, next_key, prev, prev_key) \
    __attribute__((section(".mysec2,\"awx\",@progbits#"))) \
    __attribute__((force_align_arg_pointer)) \
    void section_ ## i(uint64_t old_seed_state){ \
        if (prev != -1 && prev != 0) encrypt(prev, prev_key, old_seed_state); \
        old_seed_state = seed_state; \
        if (fns[next] != end_sec_addr) decrypt(next, next_key, seed_state); \
        mark("eb40_flag"); \
        __asm__ __volatile__(".byte 0xeb, 0x20"); \
        { \
            register uint64_t rdi_val asm("rdi") = old_seed_state; \
            asm volatile ("jmp *%0":: "r"(fns[next]), "r"(rdi_val) : "memory"); \
        } \
        __asm__ __volatile__(".fill 0x20, 1, 0x90"); \
        mark("flag_begin"); \
        if (runno == 0) no_codex_func(); \
        register uint64_t rdi_val asm("rdi") = old_seed_state; \
        asm volatile ("jmp *%0":: "r"(fns[next]), "r"(rdi_val) : "memory"); \
        mark("flag_end"); \
    }

#define SEC_FAKE_FLAG(i, next, next_key, prev, prev_key) \
    __attribute__((section(".mysec2,\"awx\",@progbits#"))) \
    __attribute__((force_align_arg_pointer)) \
    void section_ ## i(uint64_t old_seed_state){ \
        if (prev != -1 && prev != 0) encrypt(prev, prev_key, old_seed_state); \
        old_seed_state = seed_state; \
        if (fns[next] != end_sec_addr) decrypt(next, next_key, seed_state); \
        mark("eb40_fakeflag"); \
        __asm__ __volatile__(".byte 0x90, 0x90"); \
        { \
            register uint64_t rdi_val asm("rdi") = old_seed_state; \
            asm volatile ("jmp *%0":: "r"(fns[next]), "r"(rdi_val) : "memory"); \
        } \
        __asm__ __volatile__(".fill 0x20, 1, 0x90"); \
        if (runno == 0) codex_func(); \
        register uint64_t rdi_val asm("rdi") = old_seed_state; \
        asm volatile ("jmp *%0":: "r"(fns[next]), "r"(rdi_val) : "memory"); \
    }

#include "generated.h"

__attribute__((section(".mysec2,\"awx\",@progbits#")))
__attribute__((force_align_arg_pointer))
void end_sec(uint64_t old_seed_state){
    encrypt(LAST_SEC, LAST_SEC, old_seed_state);
    if (runno == 0) {
        runno++;
        seed_state = saved_seed_state;
        asm volatile ("jmp *%0":: "r"(fns[0]) : "memory");
    } else {
        kill(main_pid, SIGTERM);
        _exit(0);
    }
}

void quiet_segfault_handler(int sig) {
    _exit(0); 
}

int __attribute__((section(".mysec"))) prepare(){
    seed_state = rand64();
    saved_seed_state = seed_state;
    for (int i = 1; i<(sizeof(keytable) / sizeof(int)); i++){
        uint64_t curr_seed = seed_state;
        int cr = 0;
        while (1) {
            if (junktable[cr] != NULL){
                curr_seed = ((uint64_t (*)(uint64_t))junktable[cr])(curr_seed);
                curr_seed = ((uint64_t (*)(uint64_t))junktable2[cr])(curr_seed);
            }
            if (fdtable[cr] == i) {
                break;
            }
            cr = fdtable[cr];
        }
        encrypt(i, keytable[i], curr_seed);
    }
    ran = 1;
    puts(E("ok binary generated"));
    write_section(bp, E(".mysec2"));
    write_section(bp, E(".datasec"));
    null_section(bp, E(".mysec"));
    null_section(bp, E(".keysec"));
}

int main(int argc, char* argv[]){
    srand(time(NULL));
    strcpy(bp, argv[0]);
    end_sec_addr = (void*)end_sec;
    fns[sizeof(fns)/sizeof(void*) - 1] = end_sec;
    if (ran){
        main_pid = getpid();
        parent_pid = getppid();
        struct sigaction sa;
        sa.sa_handler = quiet_segfault_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGALRM, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        seed_state = saved_seed_state;
        printf("enter the flag: ");
        gets(flag);
        puts("please hold while we compute your flag...");
        asm volatile ("jmp *%0":: "r"(fns[0]) : "memory");
    } else {
        prepare(argv[0]);
    } 
}
