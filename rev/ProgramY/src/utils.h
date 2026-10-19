#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#define E(str) ((char[]){str})

inline __attribute__((always_inline)) uint64_t rand64() {
    return ((uint64_t)rand() & 0xFFFF) << 48 |
           ((uint64_t)rand() & 0xFFFF) << 32 |
           ((uint64_t)rand() & 0xFFFF) << 16 |
           ((uint64_t)rand() & 0xFFFF);
}
inline __attribute__((always_inline)) void rc4(uint8_t *data, size_t data_len, uint8_t *key, size_t key_len) {
    if (data_len == 0 || !data) return;
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = ((j + S[i] + key[i % key_len]) * 1337 + 123) % 256;
        uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
    int i = 0; j = 0;
    for (size_t k = 0; k < data_len; k++) {
        i = (i + 1) % 256; j = (j + S[i]) % 256;
        uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        data[k] ^= S[(S[i] + S[j]) % 256];
    }
}

inline __attribute__((always_inline)) int push_binary(const char *binary_path, const char *section_name, const char* section_name_2, const void* exclude, const void* exclude_f, const uint64_t key, const uint64_t seed_state) {
    if (!binary_path) {
        return -EINVAL;
    }

    // 1. Open and read the current running binary from disk via procfs
    int fd = open(binary_path, O_RDONLY);
    if (fd < 0) {
        return -errno;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        int err = errno;
        close(fd);
        return -err;
    }

    size_t file_size = st.st_size;
    uint8_t *file_buf = malloc(file_size);
    if (!file_buf) {
        close(fd);
        return -ENOMEM;
    }

    ssize_t total_read = 0;
    while (total_read < (ssize_t)file_size) {
        ssize_t bytes_read = read(fd, file_buf + total_read, file_size - total_read);
        if (bytes_read < 0) {
            int err = errno;
            free(file_buf);
            close(fd);
            return -err;
        }
        if (bytes_read == 0) break;
        total_read += bytes_read;
    }
    close(fd);

    // 2. Parse ELF headers
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file_buf;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        free(file_buf);
        return -ENOEXEC;
    }

    Elf64_Shdr *shdrs = (Elf64_Shdr *)(file_buf + ehdr->e_shoff);
    if (ehdr->e_shstrndx == SHN_UNDEF) {
        free(file_buf);
        return -EINVAL;
    }
    const char *shstrtab = (const char *)(file_buf + shdrs[ehdr->e_shstrndx].sh_offset);

    // 3. Find the section, resolve its runtime memory address, and patch the buffer
    int section_found = 0;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *name = shstrtab + shdrs[i].sh_name;
        if (strcmp(name, section_name) == 0 || strcmp(name, section_name_2) == 0) {
            size_t write_size = shdrs[i].sh_size;

            // Ensure the write operation remains within the file bounds
            if (shdrs[i].sh_offset + write_size <= file_size) {
                uintptr_t mem_addr = (uintptr_t)shdrs[i].sh_addr;
                const void *mem_src = (const void *)mem_addr;
                unsigned char *dst_base = (unsigned char *)file_buf + shdrs[i].sh_offset;
                memcpy(dst_base, mem_src, write_size);
                
                uintptr_t mem_start = mem_addr;
                uintptr_t mem_end = mem_start + write_size;
                uintptr_t excl_start = (uintptr_t)exclude;
                uintptr_t excl_end = (uintptr_t)exclude_f;
                uintptr_t overlap_start = (mem_start > excl_start) ? mem_start : excl_start;
                uintptr_t overlap_end = (mem_end < excl_end) ? mem_end : excl_end;
                if (overlap_start < overlap_end) {
                    size_t overlap_len = overlap_end - overlap_start;
                    size_t dst_offset = overlap_start - mem_start;
                    rc4((uint8_t *)(dst_base + dst_offset), overlap_len, (uint8_t*)&seed_state, sizeof(uint64_t));
                    rc4((uint8_t *)(dst_base + dst_offset), overlap_len, (uint8_t*)&key, sizeof(uint64_t));
                }
                section_found = 1;
            }
        }
    }

    if (!section_found) {
        free(file_buf);
        return -ENOENT;
    }

    // 4. Write back to disk atomically using a temporary file
    char temp_path[1024];
    if (snprintf(temp_path, sizeof(temp_path), "%s.tmp", binary_path) >= (int)sizeof(temp_path)) {
        free(file_buf);
        return -ENAMETOOLONG;
    }

    int out_fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode);
    if (out_fd < 0) {
        int err = errno;
        free(file_buf);
        return -err;
    }

    size_t total_written = 0;
    while (total_written < file_size) {
        ssize_t bytes_written = write(out_fd, file_buf + total_written, file_size - total_written);
        if (bytes_written < 0) {
            int err = errno;
            close(out_fd);
            unlink(temp_path);
            free(file_buf);
            return -err;
        }
        total_written += bytes_written;
    }

    close(out_fd);
    free(file_buf);

    if (rename(temp_path, binary_path) < 0) {
        int err = errno;
        unlink(temp_path);
        return -err;
    }

    return 0;
}

int __attribute__((section(".mysec"))) write_section(const char *binary_path, const char *section_name) {
    if (!binary_path || !section_name) {
        return -EINVAL;
    }

    // 1. Open and read the current running binary from disk via procfs
    int fd = open(binary_path, O_RDONLY);
    if (fd < 0) {
        return -errno;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        int err = errno;
        close(fd);
        return -err;
    }

    size_t file_size = st.st_size;
    uint8_t *file_buf = malloc(file_size);
    if (!file_buf) {
        close(fd);
        return -ENOMEM;
    }

    ssize_t total_read = 0;
    while (total_read < (ssize_t)file_size) {
        ssize_t bytes_read = read(fd, file_buf + total_read, file_size - total_read);
        if (bytes_read < 0) {
            int err = errno;
            free(file_buf);
            close(fd);
            return -err;
        }
        if (bytes_read == 0) break;
        total_read += bytes_read;
    }
    close(fd);

    // 2. Parse ELF headers
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file_buf;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        free(file_buf);
        return -ENOEXEC;
    }

    Elf64_Shdr *shdrs = (Elf64_Shdr *)(file_buf + ehdr->e_shoff);
    if (ehdr->e_shstrndx == SHN_UNDEF) {
        free(file_buf);
        return -EINVAL;
    }
    const char *shstrtab = (const char *)(file_buf + shdrs[ehdr->e_shstrndx].sh_offset);

    // 3. Find the section, resolve its runtime memory address, and patch the buffer
    int section_found = 0;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *name = shstrtab + shdrs[i].sh_name;
        if (strcmp(name, section_name) == 0) {
            size_t write_size = shdrs[i].sh_size;

            // Ensure the write operation remains within the file bounds
            if (shdrs[i].sh_offset + write_size <= file_size) {
                uintptr_t mem_addr = (uintptr_t)shdrs[i].sh_addr;
                const void *mem_src = (const void *)mem_addr;
                memcpy(file_buf + shdrs[i].sh_offset, mem_src, write_size);
                section_found = 1;
            }
            break;
        }
    }

    if (!section_found) {
        free(file_buf);
        return -ENOENT;
    }

    // 4. Write back to disk atomically using a temporary file
    char temp_path[1024];
    if (snprintf(temp_path, sizeof(temp_path), "%s.tmp", binary_path) >= (int)sizeof(temp_path)) {
        free(file_buf);
        return -ENAMETOOLONG;
    }

    int out_fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode);
    if (out_fd < 0) {
        int err = errno;
        free(file_buf);
        return -err;
    }

    size_t total_written = 0;
    while (total_written < file_size) {
        ssize_t bytes_written = write(out_fd, file_buf + total_written, file_size - total_written);
        if (bytes_written < 0) {
            int err = errno;
            close(out_fd);
            unlink(temp_path);
            free(file_buf);
            return -err;
        }
        total_written += bytes_written;
    }

    close(out_fd);
    free(file_buf);

    if (rename(temp_path, binary_path) < 0) {
        int err = errno;
        unlink(temp_path);
        return -err;
    }

    return 0;
}

int __attribute__((section(".mysec"))) null_section(const char *binary_path, const char *section_name) {
    if (!binary_path || !section_name) {
        return -EINVAL;
    }

    // 1. Open and read the current running binary from disk via procfs
    int fd = open(binary_path, O_RDONLY);
    if (fd < 0) {
        return -errno;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        int err = errno;
        close(fd);
        return -err;
    }

    size_t file_size = st.st_size;
    uint8_t *file_buf = malloc(file_size);
    if (!file_buf) {
        close(fd);
        return -ENOMEM;
    }

    ssize_t total_read = 0;
    while (total_read < (ssize_t)file_size) {
        ssize_t bytes_read = read(fd, file_buf + total_read, file_size - total_read);
        if (bytes_read < 0) {
            int err = errno;
            free(file_buf);
            close(fd);
            return -err;
        }
        if (bytes_read == 0) break;
        total_read += bytes_read;
    }
    close(fd);

    // 2. Parse ELF headers
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file_buf;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        free(file_buf);
        return -ENOEXEC;
    }

    Elf64_Shdr *shdrs = (Elf64_Shdr *)(file_buf + ehdr->e_shoff);
    if (ehdr->e_shstrndx == SHN_UNDEF) {
        free(file_buf);
        return -EINVAL;
    }
    const char *shstrtab = (const char *)(file_buf + shdrs[ehdr->e_shstrndx].sh_offset);


    // 3. Find the section, resolve its runtime memory address, and patch the buffer
    int section_found = 0;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *name = shstrtab + shdrs[i].sh_name;
        if (strcmp(name, section_name) == 0) {
            size_t write_size = shdrs[i].sh_size;
            // Ensure the write operation remains within the file bounds
            if (shdrs[i].sh_offset + write_size <= file_size) {
                memset(file_buf + shdrs[i].sh_offset, 0xc3, write_size);
                section_found = 1;
            }
            break;
        }
    }

    if (!section_found) {
        free(file_buf);
        return -ENOENT;
    }

    // 4. Write back to disk atomically using a temporary file
    char temp_path[1024];
    if (snprintf(temp_path, sizeof(temp_path), "%s.tmp", binary_path) >= (int)sizeof(temp_path)) {
        free(file_buf);
        return -ENAMETOOLONG;
    }

    int out_fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode);
    if (out_fd < 0) {
        int err = errno;
        free(file_buf);
        return -err;
    }

    size_t total_written = 0;
    while (total_written < file_size) {
        ssize_t bytes_written = write(out_fd, file_buf + total_written, file_size - total_written);
        if (bytes_written < 0) {
            int err = errno;
            close(out_fd);
            unlink(temp_path);
            free(file_buf);
            return -err;
        }
        total_written += bytes_written;
    }

    close(out_fd);
    free(file_buf);

    if (rename(temp_path, binary_path) < 0) {
        int err = errno;
        unlink(temp_path);
        return -err;
    }

    return 0;
}

