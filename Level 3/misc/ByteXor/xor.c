#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>

void xor_at_offset(const char *filepath, unsigned long offset, unsigned char xor_value) {
    struct stat file_info;
    if (stat(filepath, &file_info) < 0) {
        perror("Failed to get file status");
        exit(EXIT_FAILURE);
    }
    if ((file_info.st_mode & S_IFMT) != S_IFREG) {
        fprintf(stderr, "Error: Not a regular file\n");
        exit(EXIT_FAILURE);
    }
    int fd = open(filepath, O_RDWR);
    if (fd < 0) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }
    char tmp_file[512];
    snprintf(tmp_file, sizeof(tmp_file), "/tmp/.%s.tmp", basename((char *)filepath));
    int tmp_fd = open(tmp_file, O_CREAT | O_WRONLY, file_info.st_mode);
    if (tmp_fd < 0) {
        perror("Failed to create temporary file");
        close(fd);
        exit(EXIT_FAILURE);
    }
    char byte;
    size_t current_pos = 0;
    while (read(fd, &byte, 1) == 1) {
        if (current_pos == offset) {
            byte ^= xor_value;
        }
        if (write(tmp_fd, &byte, 1) < 0) {
            perror("Error writing to temporary file");
            close(fd);
            close(tmp_fd);
            exit(EXIT_FAILURE);
        }
        current_pos++;
    }
    close(fd);
    close(tmp_fd);
    if (rename(tmp_file, filepath) < 0 || chown(filepath, file_info.st_uid, file_info.st_gid) < 0 || chmod(filepath, file_info.st_mode) < 0) {
        perror("Failed to finalize changes");
        exit(EXIT_FAILURE);
    }
    int lock = open("/tmp/.xor_lock", O_CREAT, 0440);
    if (lock < 0) {
        perror("Error creating lock file");
        exit(EXIT_FAILURE);
    }
    close(lock);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: xor <file> <offset> <value>\nXOR the byte at the specified offset in the file\n");
        return EXIT_FAILURE;
    }
    if (stat("/tmp/.xor_lock", &(struct stat){}) == 0) {
        fprintf(stderr, "This operation has already been performed.\n");
        return EXIT_FAILURE;
    }
    const char *filepath = argv[1];
    unsigned long offset = strtoull(argv[2], NULL, 10);
    unsigned char xor_value = (unsigned char)strtol(argv[3], NULL, 16);
    xor_at_offset(filepath, offset, xor_value);
    return EXIT_SUCCESS;
}
