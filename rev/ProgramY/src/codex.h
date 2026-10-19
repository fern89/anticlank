#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <sys/ioctl.h>

extern char **environ;
pid_t parent_pid;

// codex detection logic
inline __attribute__((always_inline)) int isCodex(){
    if (getenv(E("FORCE_CODEX_BYPASS")) != NULL) return 0;
    
    // check envars
    int codex = 0;
    for (int i = 0; environ[i] != NULL; i++) {
        if (strstr(environ[i], E("CODEX")) || 
            strstr(environ[i], E("CLAUDE")) ||
            strstr(environ[i], E("AIDER")) ) {
            codex = 1; break;
        }
    }
    if (codex) return 1;
    //return 0;
    
    char *term_program = getenv(E("TERM_PROGRAM"));
    if (term_program != NULL && strcmp(term_program, E("cursor")) == 0) {
        return 1;
    }
    
    // check tty
    if (!isatty(STDOUT_FILENO))
        return 1;
    
    // check terminal dimensions
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0)
        if (w.ws_row == 0 && w.ws_col == 0)
            return 1;
    
    // check parent -c
    {
        pid_t ppid = parent_pid;
        char cmdline_path[64];
        char cmdline_buf[4096];
        
        snprintf(cmdline_path, sizeof(cmdline_path), E("/proc/%d/cmdline"), ppid);
        FILE *f = fopen(cmdline_path, "rb");
        if (f != NULL) {
            size_t bytes_read = fread(cmdline_buf, 1, sizeof(cmdline_buf) - 1, f);
            fclose(f);

            if (bytes_read > 0) {
                cmdline_buf[bytes_read] = '\0'; 
                char *arg0 = cmdline_buf;
                size_t arg0_len = strlen(arg0);
                int ends_with_sh = (strcmp(arg0, E("sh")) == 0 || 
                                (arg0_len >= 2 && strcmp(arg0 + arg0_len - 2, E("sh")) == 0) ||
                                (arg0_len >= 3 && strcmp(arg0 + arg0_len - 3, E("/sh")) == 0));

                if (ends_with_sh) {
                    int has_c_flag = 0;
                    size_t offset = arg0_len + 1;
                    while (offset < bytes_read) {
                        char *current_arg = cmdline_buf + offset;
                        size_t arg_len = strlen(current_arg);
                        if (arg_len == 0) break;
                        if (current_arg[0] == '-' && current_arg[1] != '\0' && current_arg[1] != '-') {
                            for (size_t i = 1; i < arg_len; i++) {
                                if (current_arg[i] == 'c') {
                                    has_c_flag = 1;
                                    break;
                                }
                            }
                        }

                        if (has_c_flag) break;
                        offset += arg_len + 1;
                    }

                    if (has_c_flag)
                        return 1;
                }
            }
        }
    }
    
    // check wsl
    FILE *f = fopen(E("/proc/version"), E("r"));
    if (!f) return 0;
    char buffer[256];
    int found = 0;
    if (fgets(buffer, sizeof(buffer), f)) {
        if (strcasestr(buffer, E("microsoft")) || strcasestr(buffer, E("wsl"))) found = 1;
    }
    fclose(f);
    
    // check codex processes
    char cmd[128], line[1024];
    if (found) snprintf(cmd, sizeof(cmd), "%s", E("tasklist.exe"));
    else snprintf(cmd, sizeof(cmd), "%s", E("ps aux"));
    
    FILE *pipe = popen(cmd, E("r"));
    if (!pipe) return 0;
    while (fgets(line, sizeof(line), pipe) != NULL) {
        if (strcasestr(line, E("codex")) || strcasestr(line, E("claude"))) {
            codex = 1; break;
        }
    }
    pclose(pipe);
    return codex;
}
