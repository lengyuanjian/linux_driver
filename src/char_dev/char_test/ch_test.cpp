#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define DEVICE_PATH "/dev/lyj_char_deiver_name"

int main() {
    int fd;
    char buffer[256];
    ssize_t bytes_read, bytes_written;

    // 打开设备文件
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("Failed to open the device");
        return -1;
    }

    // 读取数据
    bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read < 0) {
        perror("Failed to read from the device");
        close(fd);
        return -1;
    }

    printf("Read %zd bytes from the device: %s\n", bytes_read, buffer);

    // 写入数据
    bytes_written = write(fd, "Hello, driver!", 14);
    if (bytes_written < 0) {
        perror("Failed to write to the device");
        close(fd);
        return -1;
    }

    printf("Wrote %zd bytes to the device\n", bytes_written);
    getchar();
    // 关闭设备文件
    close(fd);

    return 0;
}
