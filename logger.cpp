#include "logger.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <pwd.h>
#include <fcntl.h>  
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <sys/user.h>
#include<iostream>
#include <cstring>
#include <stdio.h>

#define ERR -1
#define PROC_PATH "/proc"
#define FD_PATH "/fd"
// #define PATH_MAX 256

using namespace std;


Logger::Logger(std::string outputToFile, std::string loggerPath)
{
    m_insyscall = 0;
    m_fdIO = 1;
    m_outputToFile = outputToFile;
    m_loggerPath = loggerPath;
    // printf("%s %s\n", m_outputToFile.c_str(), m_loggerPath.c_str());
    if (m_outputToFile != ""){
        m_fdFile = createIOFile(outputToFile);
    }
}

Logger::~Logger()
{
    if (m_fdFile != -1)
    {
        close(m_fdFile);
    }
    if (m_fdIO != -1)
    {
        close(m_fdIO);
    }
}

int Logger::createIOFile(std::string outputToFile){
    m_fdFile = open(outputToFile.c_str(), O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
    if (m_fdFile != -1)
    {
        dup2(m_fdFile, m_fdIO);
    }
    return m_fdFile;
}

int Logger::readFileToVector(string filePath, std::vector<std::string> &datas)
{
    std::ifstream ifs(filePath, std::ios::in);
    if (!ifs.is_open()) {
        // printf("Failed to open file Path = %s\n", filePath.c_str());
        return ERR;
    } else {
        std::string s;
        while (std::getline(ifs, s)) {
            datas.push_back(s);
        }
        ifs.close();
    }
    ifs.close();
    return 0;
}

bool Logger::isNumber(const std::string& str)
{
    for (uint i = 0; i < str.length(); i++) {
        if (std::isdigit(str[i]) == 0) return false;
    }
    return true;
}

int Logger::getDirList(std::string path, std::vector<std::string> &dirlist)
{
    DIR *dp;
    struct dirent *dirp;    
    if ((dp = opendir(path.c_str())) == NULL)
    {
        // printf("path %s read fial\n", path.c_str());
        return ERR;
    }
    while ((dirp = readdir(dp)) != NULL)
    {
        if (isNumber(dirp->d_name)) dirlist.push_back(dirp->d_name);
    }
    return 0;
}

int Logger::getLink(std::string path, std::string &link)
{
    char buf[1024];
    ssize_t len = readlink(path.c_str(), buf, sizeof(buf));
    if (len != std::string::npos)
    {
        buf[len] = '\0';
        link = std::string(buf, len);
        return 0;
    }
    else
    {
        return ERR;
    }
}

int Logger::getFd(pid_t pid, int fd, std::string &link)
{
    char pid_str[6];
    sprintf(pid_str, "%ld", (long)pid);
    std::string fd_str = std::to_string(fd);
    std::string path = std::string(PROC_PATH) + "/" + std::string(pid_str) + std::string(FD_PATH) + "/" + fd_str;
    int ret = getLink(path, link);
    return ret;
}

void Logger::getMsg(pid_t pid, long addr, int len, std::string &msg)
{
    char *buff, tmp;
    long i, j, value, offset;
    union {
            long value;
            char chars[sizeof(long)];
    } data;
    buff = (char *)malloc(len + 1);
    if (buff == NULL)
        exit(1);
    for (i = 0, offset = 0; i < len / (long)sizeof(long); i++, offset += sizeof(long)) {
            value = ptrace(PTRACE_PEEKDATA, pid, addr + offset, NULL);
            memcpy(buff + offset, &value, sizeof(long));
    }
    if (len % sizeof(long)) {
            value = ptrace(PTRACE_PEEKDATA, pid, addr + offset, NULL);
            memcpy(buff + offset, &value, len % sizeof(long));
    }
    buff[len] = 0;
    msg.assign(buff, len);
    free(buff);
    // printf("msg = %c\n", buff);
    return;
}

void Logger::getMsg(pid_t pid, long addr, std::string &msg)
{
    char *buff, tmp;
    long i, j, value, offset;
    union {
            long value;
            char chars[sizeof(long)];
    } data;
    buff = (char *)malloc(PATH_MAX);
    if (buff == NULL)
        exit(1);
    for (i = 0, offset = 0; i < PATH_MAX / (long)sizeof(long); i++, offset += sizeof(long)) {
            value = ptrace(PTRACE_PEEKDATA, pid, addr + offset, NULL);
            if (&value == 0) break;
            memcpy(buff + offset, &value, sizeof(long));
    }
    // if (len % sizeof(long)) {
    //         value = ptrace(PTRACE_PEEKDATA, pid, addr + offset, NULL);
    //         memcpy(buff + offset, &value, len % sizeof(long));
    // }
    buff[i] = 0;
    msg.assign(buff, i);
    free(buff);
    // printf("getMsg = %s\n", msg.c_str());
    return;
}

void Logger::getRealPath(pid_t pid, long addr, std::string &msg)
{
    char path[PATH_MAX];
    char *exist;
    getMsg(pid, addr, msg);
    exist=realpath(msg.c_str(), path);
    msg.assign(path, PATH_MAX);
}

int Logger::rw2str(long rw, std::string &rwStr)
{
    if ((rw & O_RDONLY) == O_RDONLY) rwStr = "r";
    else if ((rw & O_WRONLY) == O_WRONLY) rwStr = "w";
    else if ((rw & O_RDWR) == O_RDWR) rwStr = "rw";
    return 0;
}

int Logger::sysChmod(pid_t trace_pid, std::string &msg)
{
    long params[3];
    long eax;
    if(m_insyscall == 0) 
    {
        /* Syscall entry */
        m_insyscall = 1;
        params[0] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDI,
                        NULL);
        params[1] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RSI,
                        NULL);
        string msg_pathname = "";
        mode_t mode = (mode_t)params[1];
        getRealPath(trace_pid, params[0], msg_pathname);
        char cmsg[PATH_MAX];
        sprintf(cmsg, "[logger] chmod(\"%s\", %o)", msg_pathname.c_str(), mode);
        msg.assign(cmsg, PATH_MAX);
    }
    else
    { 
        /* Syscall exit */
        eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * RAX, NULL);
        fprintf(stderr,"%s = %ld\n", msg.c_str(), eax);
        msg = "";
        m_insyscall = 0;
    }
    return 0;
}

int Logger::sysRead(pid_t trace_pid, std::string &msg)
{
        long params[3];
    long eax;
    if(m_insyscall == 0) 
    {
        /* Syscall entry */
        m_insyscall = 1;
        params[0] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDI,
                        NULL);
        params[1] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RSI,
                        NULL);
        params[2] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDX,
                        NULL);
        string msg_fd = "";
        string msg_buf = "";
        string msg_count = std::to_string(params[2]);
        getFd(trace_pid, params[0], msg_fd);
        getMsg(trace_pid, params[1], params[2] - 1, msg_buf);
        char cmsg[PATH_MAX];
        sprintf(cmsg, "[logger] read(\"%s\", \"%s\", %s)", msg_fd.c_str(), msg_buf.c_str(), msg_count.c_str());
        msg.assign(cmsg, PATH_MAX);
    }
    else
    { 
        /* Syscall exit */
        eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * RAX, NULL);
        fprintf(stderr, "%s = %ld\n", msg.c_str(), eax);
        msg = "";
        m_insyscall = 0;
    }
    return 0;
}

int Logger::sysCreat(pid_t trace_pid, std::string &msg)
{
    long params[3];
    long eax;
    if(m_insyscall == 0) 
    {
        /* Syscall entry */
        m_insyscall = 1;
        params[0] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDI,
                        NULL);
        params[1] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RSI,
                        NULL);
        string msg_pathname = "";
        mode_t mode = (mode_t)params[1];
        getRealPath(trace_pid, params[0], msg_pathname);
        char cmsg[PATH_MAX];
        sprintf(cmsg, "[logger] creat(\"%s\", %o)", msg_pathname.c_str(), mode);
        msg.assign(cmsg, PATH_MAX);
    }
    else
    { 
        /* Syscall exit */
        eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * RAX, NULL);
        fprintf(stderr, "%s = %ld\n", msg.c_str(), eax);
        msg = "";
        m_insyscall = 0;
    }
    return 0;
}

int Logger::sysChown(pid_t trace_pid, std::string &msg)
{
    long params[3];
    long eax;
    if(m_insyscall == 0) 
    {
        /* Syscall entry */
        m_insyscall = 1;
        params[0] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDI,
                        NULL);
        params[1] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RSI,
                        NULL);
        params[2] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDX,
                        NULL);
        string msg_pathname = "";
        getRealPath(trace_pid, params[0], msg_pathname);

        uid_t uid = (uid_t)params[1];
        gid_t gid = (gid_t)params[2];

        char cmsg[PATH_MAX];
        sprintf(cmsg, "[logger] chown(\"%s\", %ld, %ld)", msg_pathname.c_str(), (unsigned long int)uid, (unsigned long int)gid);
        msg.assign(cmsg, PATH_MAX);
    }
    else
    { 
        /* Syscall exit */
        eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * RAX, NULL);
        fprintf(stderr, "%s = %ld\n", msg.c_str(), eax);
        msg = "";
        m_insyscall = 0;
    }
    return 0;
}

int Logger::sysRename(pid_t trace_pid, std::string &msg)
{
    long params[3];
    long eax;
    if(m_insyscall == 0) 
    {
        /* Syscall entry */
        m_insyscall = 1;
        params[0] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDI,
                        NULL);
        params[1] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RSI,
                        NULL);
        string msg_oldpath = "";
        string msg_newpath = "";
        getRealPath(trace_pid, params[0], msg_oldpath);
        getRealPath(trace_pid, params[1], msg_newpath);
        char cmsg[PATH_MAX];
        sprintf(cmsg, "[logger] rename(\"%s\", \"%s\")", msg_oldpath.c_str(), msg_newpath.c_str());
        msg.assign(cmsg, PATH_MAX);
    }
    else
    { 
        /* Syscall exit */
        eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * RAX, NULL);
        fprintf(stderr, "%s = %ld\n", msg.c_str(), eax);
        msg = "";
        m_insyscall = 0;
    }
    return 0;
}

int Logger::sysWrite(pid_t trace_pid, std::string &msg)
{
    long params[3];
    long eax;
    if(m_insyscall == 0) 
    {
        /* Syscall entry */
        m_insyscall = 1;
        params[0] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDI,
                        NULL);
        params[1] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RSI,
                        NULL);
        params[2] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDX,
                        NULL);
        string msg_fd = "";
        string msg_buf = "";
        string msg_count = std::to_string(params[2]);
        getFd(trace_pid, params[0], msg_fd);
        getMsg(trace_pid, params[1], params[2] - 1, msg_buf);
        char cmsg[PATH_MAX];
        sprintf(cmsg, "[logger] write(\"%s\", \"%s\", %s)", msg_fd.c_str(), msg_buf.c_str(), msg_count.c_str());
        msg.assign(cmsg, PATH_MAX);

        printf("write ====== %ld %ld %ld\n", params[0], params[1], params[2]);
    }
    else
    { 
        /* Syscall exit */
        eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * RAX, NULL);
        fprintf(stderr, "%s = %ld\n", msg.c_str(), eax);
        msg = "";
        m_insyscall = 0;
    }
    return 0;
}

int Logger::sysOpenat(pid_t trace_pid, std::string &msg)
{
    long params[3];
    if(m_insyscall == 0) 
    {
        /* Syscall entry */
        m_insyscall = 1;
        params[0] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDI,
                        NULL);
        params[1] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RSI,
                        NULL);
        params[2] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDX,
                        NULL);

        std::string msg_pathname = "";
        getMsg(trace_pid, params[1], msg_pathname);
        std::string msg_flags = "";
        rw2str(params[2], msg_flags);
        char cmsg[PATH_MAX];
        sprintf(cmsg, "[logger] open(\"%s\", \"%s\")", msg_pathname.c_str(), msg_flags.c_str());
        msg.assign(cmsg, PATH_MAX);
        // msg = "[logger] fopen(\"" + msg_pathname + "\", G \"" + msg_flags + "\")";
        printf("openat ====== %ld %ld %ld\n", params[0], params[1], params[2]);
    }
    else
    { 
        /* Syscall exit */
        long eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * RAX, NULL);
        fprintf(stderr, "%s = %ld\n", msg.c_str(), eax);
        msg = "";
        m_insyscall = 0;
    }
}

int Logger::sysClose(pid_t trace_pid, std::string &msg)
{
    long params[1];
    long eax;
    struct user_regs_struct regs;

    if(m_insyscall == 0) 
    {
        /* Syscall entry */
        m_insyscall = 1;
        params[0] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDI,
                        NULL);
        string path_fd_msg = "";
        getFd(trace_pid, params[0], path_fd_msg);
        char cmsg[PATH_MAX];
        sprintf(cmsg, "[logger] close(\"%s\")", path_fd_msg.c_str());
        msg.assign(cmsg, PATH_MAX);
        printf("close ====== %ld\n", params[0]);
    }
    else
    { 
        /* Syscall exit */
        eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * RAX, NULL);
        fprintf(stderr, "%s = %ld\n", msg.c_str(), eax);
        msg = "";
        m_insyscall = 0;
    }
    return 0;
}

int Logger::sysRemove(pid_t trace_pid, std::string &msg)
{
    long params[1];
    long eax;
    struct user_regs_struct regs;

    if(m_insyscall == 0) 
    {
        /* Syscall entry */
        m_insyscall = 1;
        params[0] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDI,
                        NULL);
        string path_fd_msg = "";
        getFd(trace_pid, params[0], path_fd_msg);
        char cmsg[PATH_MAX];
        sprintf(cmsg, "[logger] remove(\"%s\")", path_fd_msg.c_str());
        msg.assign(cmsg, PATH_MAX);
    }
    else
    { 
        /* Syscall exit */
        eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * RAX, NULL);
        fprintf(stderr, "%s = %ld\n", msg.c_str(), eax);
        msg = "";
        m_insyscall = 0;
    }
    return 0;
}

int Logger::traceChild(pid_t trace_pid)
{
    int wstatus;
    long orig_eax, eax;
    int ret = 0;
    std::string msg = "";
    while(waitpid(trace_pid, &wstatus, 0))
    {
        if (WIFEXITED(wstatus)){
            printf("child exits\n");
            return 0;
        }
        else if(WIFSTOPPED(wstatus))
        {

            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, trace_pid, 0, &regs);
            long syscall = regs.orig_rax;
            printf("regs = %ld(%ld, %ld, %ld, %ld, %ld, %ld)\n",
                syscall,
                (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
                (long)regs.r10, (long)regs.r8,  (long)regs.r9);

            orig_eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * ORIG_RAX, NULL);
            // original_rax = ptrace(PTRACE_PEEKUSER, trace_pid, &user_space->regs.orig_rax, NULL);
            printf("orig_eax %ld\n", orig_eax);
            switch (orig_eax)
            {
            case -1:
                perror("ptrace PTRACE_PEEKUSER error");
                break;
            case SYS_read:
                ret = sysRead(trace_pid, msg);
                break;
            case SYS_chmod:
                // printf("SYS_close %ld\n", orig_eax); 
                ret = sysChmod(trace_pid, msg);
                break;
            case SYS_creat:
                ret = sysCreat(trace_pid, msg);
                break;
            case SYS_chown:
                ret = sysChown(trace_pid, msg);
                break;
            case SYS_rename:
                ret = sysRename(trace_pid, msg);
                break;
            case SYS_write:
                // printf("SYS_write %ld\n", orig_eax);
                ret = sysWrite(trace_pid, msg);
                break;
            case SYS_openat:
                // printf("SYS_openat %ld\n", orig_eax); 
                ret = sysOpenat(trace_pid, msg);
                break;
            case SYS_close:
                // printf("SYS_close %ld\n", orig_eax); 
                ret = sysClose(trace_pid, msg);
                break;
            case SYS_unlink:
                // printf("SYS_chmod %ld\n", orig_eax); 
                ret = sysRemove(trace_pid, msg);
                break;
            // case SYS_openat:
            //     printf("SYS_openat %ld\n", orig_eax);
            //     ret = sysWrite(trace_pid, m_insyscall);
            default:
                break;
            }
            // ptrace(PTRACE_SINGLESTEP, trace_pid, NULL, NULL);
            ptrace(PTRACE_SYSCALL, trace_pid, NULL, NULL);
        }
    }
    return 0;   
}

int Logger::run(int cmdId, char* argv[])
{
    pid_t pid; 
    try
    {     
        if ((pid = fork()) < 0)
        {
            perror("fork fail");
        }
        else if (pid == 0)
        {
            //child
            printf("[child]pid %d getpid %d\n", pid, getpid());
            ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            execvp(argv[cmdId], &argv[cmdId]);
        }
        else
        {
            //parent
            printf("[parent]child pid %d getpid %d\n", pid, getpid());
            int ret = traceChild(pid);
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << "run() " << e.what() << '\n';
    }     
    return 0;
}

FILE *fopen(const char *pathname, const char *mode)
{
    printf("fopen 8888\n");
    return NULL;
}