#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <memory.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/mman.h>

const char pubkey[9][72] = {
    "-----BEGIN PUBLIC KEY-----",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxqkTcfbKw8ysVygePlcB",
    "oUAhCF6oniyP13iDtu85ZsHwqw8PnMyTp6n6FnMN9YinleIAy6NFveBu/vshTN8S",
    "oXbYyy5AqdZ8CQpfvuriO9UNfgV1l7SFdPPpruFAmOw+uzA3GawMsg3QNK/htqJe",
    "b4xKHFS04xC2AueE2RTmk6tJcL8TEBfRG7DEYOHPjebKl1NQ3ZIu15U97cCPYKO2",
    "pWHzsb+Fr4Wj0DChLoxlXxaBcJ2ozogaq0tW2t4Aopvt9kRSuSK9HcgxICJM5ct4",
    "naU91WFGWlw0+0JpiMIl5OnMbpak/5xQre9DL8zM8LjRy14I88txvXvhPEsWaYCO",
    "1QIDAQAB",
    "-----END PUBLIC KEY-----"
};

void help() {
    printf("Usage:\n");
    printf("    ./navicat-patcher <navicat executable file>\n");
    printf("\n");
}

size_t search_pubkey_location(uint8_t* pFileContent, size_t FileSize) {
    static const char search_str[] = "-----BEGIN PUBLIC KEY-----";

    size_t i = 0;
    if (FileSize < sizeof(search_str) - 1) return (size_t)-1;
    FileSize -= sizeof(search_str);
    for (; i < FileSize; ++i) {
        if (pFileContent[i] == '-' && memcmp(pFileContent + i, search_str, sizeof(search_str) - 1) == 0)
            return i;
    }
    return (size_t)-1;
}

void do_patch(uint8_t* pFileContent, size_t offset) {
    strcpy(pFileContent + offset, pubkey[0]);
    offset += strlen(pubkey[0]) + 1;
    
    strcpy(pFileContent + offset, pubkey[1]);
    offset += strlen(pubkey[1]) + 1;
    
    strcpy(pFileContent + offset, pubkey[2]);
    offset += strlen(pubkey[2]) + 1;
    
    strcpy(pFileContent + offset, pubkey[3]);
    offset += strlen(pubkey[3]) + 1;
    
    strcpy(pFileContent + offset, pubkey[4]);
    offset += strlen(pubkey[4]) + 1;
    
    strcpy(pFileContent + offset, pubkey[5]);
    offset += strlen(pubkey[5]) + 1;
    
    strcpy(pFileContent + offset, pubkey[6]);
    offset += strlen(pubkey[6]) + 1;
    
    strcpy(pFileContent + offset, pubkey[7]);
    offset += strlen(pubkey[7]) + 1;
    
    strcpy(pFileContent + offset, pubkey[8]);
    offset += strlen(pubkey[8]) + 1;
}

int main(int argc, char* argv[], char* envp[]) {
    int status = 0;
    int fd = -1;
    struct stat fd_stat = {};
    uint8_t* file_content = 0;

    if (argc != 2) {
        help();
        return 0;
    }

    fd = open(argv[1], O_RDWR, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        printf("Failed to open file. CODE: 0x%08x\n", errno);
        status = errno;
        goto main_fin;
    } else {
        printf("Open file successfully.\n");
    }

    if (fstat(fd, &fd_stat) != 0) {
        printf("Failed to get file size. CODE: 0x%08x\n", errno);
        status = errno;
        goto main_fin;
    } else {
        printf("Get file size successfully: %zu\n", fd_stat.st_size);
    }

    file_content = mmap(NULL, fd_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (file_content == (void*)-1) {
        printf("Failed to map file. CODE: 0x%08x\n", errno);
        status = errno;
        goto main_fin;
    } else {
        printf("Map file successfully.\n");
    }

    size_t offset = search_pubkey_location(file_content, fd_stat.st_size);
    if (offset == (size_t)-1) {
        printf("Failed to find pubkey location.\n");
        goto main_fin;
    }

    printf("offset = 0x%016llx\n", offset);
    
    do_patch(file_content, offset);
    printf("Success!\n");

main_fin:
    if (file_content != NULL) munmap(file_content, fd_stat.st_size);
    if (fd != -1) close(fd);
    return status;
}

