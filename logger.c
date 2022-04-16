#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define PATH_MAX 1024
#define LOGGER_FD 3
#define MAX_BUF_SIZE 32
static FILE * logger_out = NULL;
FILE *getLoggerFile(){
  if (logger_out == NULL){
    logger_out = fdopen(LOGGER_FD, "w");
  }
  return logger_out;
}

int fileToPath(FILE *stream, char *filename)
{
    char proclnk[PATH_MAX] = "";
    int fno;
    ssize_t r;

    // test.txt created earlier
    if (stream != NULL)
    {
        fno = fileno(stream);
        sprintf(proclnk, "/proc/self/fd/%d", fno);
        r = readlink(proclnk, filename, PATH_MAX);
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
    char proclnk[PATH_MAX] = "";
    ssize_t r;
    // fno = fno -2;
    // test.txt created earlier
    if (fno > 0)
    {
        sprintf(proclnk, "/proc/self/fd/%d", fno);
        // printf("proclnk %s\n", proclnk);
        r = readlink(proclnk, filename, PATH_MAX);
        if (r < 0)
        {
            printf("failed to readlink\n");
            exit(1);
        }
        filename[r] = '\0';
        // printf("proclnk %ld, %s\n", r, filename);
        // printf("stream -> fno -> filename: %p -> %d -> %s\n",
        //         stream, fno, filename);
    }
    else
    {
      filename = "";
      return -1;
    }
    return 0;
}

void getRealPath(const char * pathname, char * real)
{
  char *exist;
  exist=realpath(pathname, real);
  return;
}

void checkBuf(const char * buf, char * newBuff, size_t len)
{
  // printf("%ld\n", len);
  for (int i = 0; i < len; ++i)
  {
    if (i >= MAX_BUF_SIZE)
    {
      newBuff[i] = '\0';
      break;
    } 
    // fprintf(getLoggerFile(), "[buf] isprint =%c %d\n",buf[i], isprint(buf[i]));
    if (isprint(buf[i]) == 0)
    {
      newBuff[i] = '.';
    }
    else
    {
      newBuff[i] = buf[i];
    }
  }
  // int af_length = strlen(buf);
  // fprintf(getLoggerFile(), "[buf] checkBuf(\"%s\", %d, %d)\n", (char *)buf, length, af_length);
}

// static uid_t (*old_getuid)(void) = NULL; /* function pointer */
// uid_t getuid(void)
// {
//   if(old_getuid == NULL)
//   {
//     void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
//     if(handle != NULL)
//       old_getuid = dlsym(handle, "getuid");
//   }
 
//   fprintf(getLoggerFile(), "[logger]getuid\n");
 
//   if(old_getuid != NULL){
//     // fprintf(getLoggerFile(), "real uid = %d\n", old_getuid());
//     return old_getuid();
//   }
//   return 0;
// }

static FILE * (*old_fopen)(const char *, const char *) = NULL; /* function pointer */
FILE *fopen(const char *pathname, const char *mode)
{
  char realPath[PATH_MAX] = "";
  if(old_fopen == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_fopen = dlsym(handle, "fopen");
  }
  if(old_fopen != NULL){
    // fprintf(getLoggerFile(), "real fopen = %p\n", old_fopen(pathname, mode));
    getRealPath(pathname, realPath);
    FILE * f = old_fopen(pathname, mode);
    fprintf(getLoggerFile(), "[logger] fopen(\"%s\", \"%s\") = %p\n", realPath, mode, f);
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
    char filename[PATH_MAX] = "";
    fileToPath(stream, filename);
    int ret = old_fclose(stream);
    fprintf(getLoggerFile(), "[logger] fclose(\"%s\") = %d\n", filename, ret);
    return ret;
  }
  return 0;
}

static size_t (*old_fwrite)(const void *, size_t, size_t, FILE *) = NULL; /* function pointer */
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  char filename[PATH_MAX] = "";
  char newBuf[MAX_BUF_SIZE] = "";
  if(old_fwrite == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_fwrite = dlsym(handle, "fwrite");
  }
  if(old_fwrite != NULL){
    fileToPath(stream, filename);
    size_t ret = old_fwrite(ptr, size, nmemb, stream);
    checkBuf((char *)ptr, newBuf, size * nmemb);
    fprintf(getLoggerFile(), "[logger] fwrite(\"%s\", %ld, %ld, \"%s\") = %ld\n", (char *)newBuf, size, nmemb, filename, ret);
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
    fprintf(getLoggerFile(), "[logger] chmod(\"%s\", %o) = %d\n", pathname, mode, ret);
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
    fprintf(getLoggerFile(), "[logger] creat(\"%s\", %o) = %d\n", pathname, mode, ret);
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
    fprintf(getLoggerFile(), "[logger] chown(\"%s\", %d, %d) = %d\n", pathname, owner, group, ret);
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
    fprintf(getLoggerFile(), "[logger] rename(\"%s\", \"%s\") = %d\n", oldpath, newpath, ret);
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
    fprintf(getLoggerFile(), "[logger] open(\"%s\", %o, %o) = %d\n", pathname, flags, mode, ret);
    return ret;
  }
  return 0;
}

static ssize_t (*old_write)(int, const void *, size_t) = NULL; /* function pointer */
ssize_t write(int fd, const void *buf, size_t count)
{
  char newBuf[MAX_BUF_SIZE] = "";
  if(old_write == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_write = dlsym(handle, "write");
  }
  if(old_write != NULL){
    char filename[PATH_MAX] = "";
    fdToPath(fd, filename);
    int ret = old_write(fd, buf, count);
    checkBuf((char *)buf, newBuf, count);
    fprintf(getLoggerFile(), "[logger] write(\"%s\", \"%s\", %ld) = %d\n", filename, (char *)newBuf, count, ret);
    return ret;
  }
  return 0;
}

static ssize_t (*old_read)(int, const void *, size_t) = NULL; /* function pointer */
ssize_t read(int fd, void *buf, size_t count)
{
  char newBuf[MAX_BUF_SIZE] = "";
  if(old_read == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_read = dlsym(handle, "read");
  }
  if(old_read != NULL){
    char filename[PATH_MAX] = "";
    fdToPath(fd, filename);
    int ret = old_read(fd, buf, count);
    checkBuf((char *)buf, newBuf, count);
    fprintf(getLoggerFile(), "[logger] read(\"%s\", \"%s\", %ld) = %d\n", filename, (char *)newBuf, count, ret);
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
    char filename[PATH_MAX] = "";
    fdToPath(fd, filename);
    int ret = old_close(fd);
    fprintf(getLoggerFile(), "[logger] close(\"%s\") = %d\n", filename, ret);
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
    fprintf(getLoggerFile(), "[logger] tmpfile() = %p\n", ret);
    return ret;
  }
  return 0;
}

static int (*old_remove)(const char *) = NULL; /* function pointer */
int remove(const char *pathname)
{
  char realPath[PATH_MAX] = "";
  if(old_remove == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_remove = dlsym(handle, "remove");
  }
  if(old_remove != NULL){
    getRealPath(pathname, realPath);
    int ret = old_remove(pathname);
    fprintf(getLoggerFile(), "[logger] remove(\"%s\") = %d\n",realPath, ret);
    return ret;
  }
  return 0;
}

static int (*old_fread)(void *ptr, size_t, size_t, FILE *) = NULL; /* function pointer */
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  char filename[PATH_MAX] = "";
  char newBuf[MAX_BUF_SIZE] = "";
  if(old_fwrite == NULL)
  {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
 
    if(handle != NULL)
      old_fwrite = dlsym(handle, "fread");
  }
  if(old_fwrite != NULL){
    fileToPath(stream, filename);
    size_t ret = old_fwrite(ptr, size, nmemb, stream);
    checkBuf((char *)ptr, newBuf, size * nmemb);
    fprintf(getLoggerFile(), "[logger] fread(\"%s\", %ld, %ld, \"%s\") = %ld\n", (char *)newBuf, size, nmemb, filename, ret);
    return ret;
  }
  return 0;
}