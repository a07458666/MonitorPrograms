#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>

#define PATH_MAX 1024

int fileToPath(FILE *stream, char *filename)
{
    int MAXSIZE = 0xFFF;
    char proclnk[0xFFF];
    int fno;
    ssize_t r;

    // test.txt created earlier
    if (stream != NULL)
    {
        fno = fileno(stream);
        sprintf(proclnk, "/proc/self/fd/%d", fno);
        r = readlink(proclnk, filename, MAXSIZE);
        if (r < 0)
        {
            printf("failed to readlink\n");
            exit(1);
        }
        filename[r] = '\0';
        // printf("stream -> fno -> filename: %p -> %d -> %s\n",
        //         stream, fno, filename);
    }
    return 0;
}

int fdToPath(int fno, char *filename)
{
    int MAXSIZE = 0xFFF;
    char proclnk[0xFFF];
    ssize_t r;
    // fno = fno -2;
    // test.txt created earlier
    if (fno > 0)
    {
        sprintf(proclnk, "/proc/self/fd/%d", fno);
        // printf("proclnk %s\n", proclnk);
        r = readlink(proclnk, filename, MAXSIZE);
        if (r < 0)
        {
            printf("failed to readlink\n");
            exit(1);
        }
        filename[r] = '\0';
        // printf("stream -> fno -> filename: %p -> %d -> %s\n",
        //         stream, fno, filename);
    }
    return 0;
}

void getRealPath(const char * pathname, char * real)
{
  char *exist;
  exist=realpath(pathname, real);
  return;
}

static uid_t (*old_getuid)(void) = NULL; /* function pointer */
uid_t getuid(void)
{
  if(old_getuid == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_getuid = dlsym(handle, "getuid");
  }
 
  fprintf(stderr, "[logger]getuid\n");
 
  if(old_getuid != NULL){
    // fprintf(stderr, "real uid = %d\n", old_getuid());
    return old_getuid();
  }
  return 0;
}

static FILE * (*old_fopen)(const char *, const char *) = NULL; /* function pointer */
FILE *fopen(const char *pathname, const char *mode)
{
  char realPath[PATH_MAX];
  if(old_fopen == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_fopen = dlsym(handle, "fopen");
  }
  if(old_fopen != NULL){
    // fprintf(stderr, "real fopen = %p\n", old_fopen(pathname, mode));
    getRealPath(pathname, realPath);
    FILE * f = old_fopen(pathname, mode);
    fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", realPath, mode, f);
    return f;
  }
  return 0;
}

static int (*old_fclose)(FILE *) = NULL; /* function pointer */
int fclose(FILE *stream)
{
  if(old_fclose == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_fclose = dlsym(handle, "fclose");
  }
  if(old_fclose != NULL){
    char filename[0xFFF];
    fileToPath(stream, filename);
    if (stream == stderr) fprintf(stderr, "[logger] fclose(\"%s\") = 0\n", filename);
    // fprintf(stderr, "[stderr] %p %p", stream, stderr);
    int ret = old_fclose(stream);
    fprintf(stderr, "[logger] fclose(\"%s\") = %d\n", filename, ret);
    return ret;
  }
  return 0;
}

static size_t (*old_fwrite)(const void *, size_t, size_t, FILE *) = NULL; /* function pointer */
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  char filename[0xFFF];
  if(old_fwrite == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_fwrite = dlsym(handle, "fwrite");
  }
  if(old_fwrite != NULL){
    fileToPath(stream, filename);
    size_t ret = old_fwrite(ptr, size, nmemb, stream);
    fprintf(stderr, "[logger] fwrite(\"%s\", %ld, %ld, \"%s\") = %ld\n", (char *)ptr, size, nmemb, filename, ret);
    return ret;
  }
  return 0;
}

static int (*old_chmod)(const char *, mode_t) = NULL; /* function pointer */
int chmod(const char *pathname, mode_t mode)
{
  if(old_chmod == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_chmod = dlsym(handle, "chmod");
  }
  if(old_chmod != NULL){
    int ret = old_chmod(pathname, mode);
    fprintf(stderr, "[logger] chmod(\"%s\", %o) = %d\n", pathname, mode, ret);
    return ret;
  }
  return 0;
}

static int (*old_creat)(const char *, mode_t) = NULL; /* function pointer */
int creat(const char *pathname, mode_t mode)
{
  if(old_creat == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_creat = dlsym(handle, "creat");
  }
  if(old_creat != NULL){
    int ret = old_creat(pathname, mode);
    fprintf(stderr, "[logger] creat(\"%s\", %o) = %d\n", pathname, mode, ret);
    return ret;
  }
  return 0;
}

static int (*old_chown)(const char *, uid_t, gid_t) = NULL; /* function pointer */
int chown(const char *pathname, uid_t owner, gid_t group)
{
  if(old_chown == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_chown = dlsym(handle, "chown");
  }
  if(old_chown != NULL){
    int ret = old_chown(pathname, owner, group);
    fprintf(stderr, "[logger] chown(\"%s\", %d, %d) = %d\n", pathname, owner, group, ret);
    return ret;
  }
  return 0;
}

static int (*old_rename)(const char *, const char *) = NULL; /* function pointer */
int rename(const char *oldpath, const char *newpath)
{
  if(old_rename == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_rename = dlsym(handle, "rename");
  }
  if(old_rename != NULL){
    int ret = old_rename(oldpath, newpath);
    fprintf(stderr, "[logger] rename(\"%s\", \"%s\") = %d\n", oldpath, newpath, ret);
    return ret;
  }
  return 0;
}

static int (*old_open)(const char *, int, mode_t) = NULL; /* function pointer */
int open(const char *pathname, int flags, mode_t mode)
{
  if(old_open == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_open = dlsym(handle, "open");
  }
  if(old_open != NULL){
    int ret = old_open(pathname, flags, mode);
    fprintf(stderr, "[logger] open(\"%s\", %o, %o) = %d\n", pathname, flags, mode, ret);
    return ret;
  }
  return 0;
}

static ssize_t (*old_write)(int, const void *, size_t) = NULL; /* function pointer */
ssize_t write(int fd, const void *buf, size_t count)
{
  if(old_write == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_write = dlsym(handle, "write");
  }
  if(old_write != NULL){
    char filename[0xFFF];
    fdToPath(fd, filename);
    int ret = old_write(fd, buf, count);
    fprintf(stderr, "[logger] write(\"%s\", \"%s\", %ld) = %d\n", filename, (char *)buf, count, ret);
    return ret;
  }
  return 0;
}

static ssize_t (*old_read)(int, const void *, size_t) = NULL; /* function pointer */
ssize_t read(int fd, void *buf, size_t count)
{
  if(old_read == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_read = dlsym(handle, "read");
  }
  if(old_read != NULL){
    char filename[0xFFF];
    fdToPath(fd, filename);
    int ret = old_read(fd, buf, count);
    fprintf(stderr, "[logger] read(\"%s\", \"%s\", %ld) = %d\n", filename, (char *)buf, count, ret);
    return ret;
  }
  return 0;
}

static int (*old_close)(int) = NULL; /* function pointer */
int close(int fd)
{
  if(old_close == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_close = dlsym(handle, "close");
  }
  if(old_close != NULL){
    char filename[0xFFF];
    fdToPath(fd, filename);
    int ret = old_close(fd);
    fprintf(stderr, "[logger] close(\"%s\") = %d\n", filename, ret);
    return ret;
  }
  return 0;
}

static FILE * (*old_tmpfile)(void) = NULL; /* function pointer */
FILE * tmpfile(void)
{
  if(old_tmpfile == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_tmpfile = dlsym(handle, "tmpfile");
  }
  if(old_tmpfile != NULL){
    FILE * ret = old_tmpfile();
    fprintf(stderr, "[logger] tmpfile() = %p\n", ret);
    return ret;
  }
  return 0;
}

static int (*old_remove)(const char *) = NULL; /* function pointer */
int remove(const char *pathname)
{
  char realPath[PATH_MAX];
  if(old_remove == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_remove = dlsym(handle, "remove");
  }
  if(old_remove != NULL){
    getRealPath(pathname, realPath);
    int ret = old_remove(pathname);
    fprintf(stderr, "[logger] remove(\"%s\") = %d\n",realPath, ret);
    return ret;
  }
  return 0;
}