#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    int fd = open("tmp.txt", O_RDWR | O_CREAT, 0666);
    char buf[128] = "Hello world_Hello world_Hello world_Hello world\n";
    int len = sizeof(buf)/ sizeof(char);
    int ret = write(fd, buf, len);
    fprintf(stderr, "ERROR MSG\n");
    close(fd);
    return 0;
}