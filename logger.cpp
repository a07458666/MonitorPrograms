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

#define ERR -1
#define PROC_PATH "/proc"
#define FD_PATH "/fd"
#define MAX_BUFF 256

using namespace std;


Logger::Logger(std::string outputToFile, std::string loggerPath)
{
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

int Logger::sysWrite(pid_t trace_pid, int &insyscall)
{
    long params[3];
    long eax;
    if(insyscall == 0) 
    {
        /* Syscall entry */
        insyscall = 1;
        params[0] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDI,
                        NULL);
        params[1] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RSI,
                        NULL);
        params[2] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDX,
                        NULL);
        string msg = "";
        string path_fd = "";
        getMsg(trace_pid, params[1], msg);
        getFd(trace_pid, params[0], path_fd);
        printf("[logger]write(\"%s\", \"%s\", %ld) = AAAAA\n", path_fd.c_str(), msg.c_str(), params[2]);
        // printf("msg = %s\n", msg.c_str());
        // ptrace(PTRACE_GETREGS, trace_pid, NULL, &regs);
        // printf("write called with %lld, %lld, %lld.\n", regs.rdi, regs.rsi, regs.rdx);
    }
    else
    { 
        /* Syscall exit */
        eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * RAX, NULL);
        // printf("Write returned with %ld\n", eax);
        // printf("[logger] aaa(%ld, 0x%lx, %ld) = %ld\n", params[0], params[1], params[2], eax);
        insyscall = 0;
    }
}

void Logger::reverse(pid_t pid, long addr, int len = 128)
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

        for(i = 0, j = len - 2; i <= j; ++i, --j) {
                tmp = buff[i];
                buff[i] = buff[j];
                buff[j] = tmp;
        }

        for (i = 0, offset = 0; i < len / (long)sizeof(long); i++, offset += sizeof(long)) {
                memcpy(data.chars, buff + offset, sizeof(long));
                ptrace(PTRACE_POKEDATA, pid, addr + offset, data.value);
        }
        if (len % sizeof(long)) {
                memcpy(data.chars, buff + offset, sizeof(long));
                ptrace(PTRACE_POKEDATA, pid, addr + offset, data.value);
        }
        free(buff);
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
    // printf("pid_str = %s\n", pid_str);
    std::string path = std::string(PROC_PATH) + "/" + std::string(pid_str) + std::string(FD_PATH);
    // printf("%s\n", path.c_str());
    std::vector<std::string> dirList;
    int ret = getDirList(path, dirList);
    if (ret == ERR) return ERR;

    for (int i = 0; i< dirList.size(); i++)
    {
        // printf("dirList %s\n", dirList[i].c_str());
        if (std::stoi(dirList[i]) == fd)
        {
            ret = getLink(path + "/" + dirList[i], link);
            return ret;
        }
    }
    return 0;
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
    buff = (char *)malloc(MAX_BUFF);
    if (buff == NULL)
        exit(1);
    for (i = 0, offset = 0; i < MAX_BUFF / (long)sizeof(long); i++, offset += sizeof(long)) {
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
    printf("getMsg = %s\n", msg.c_str());
    return;
}

int Logger::rw2str(long rw, std::string &rwStr)
{
    rw = rw & (O_RDONLY | O_WRONLY | O_RDWR);
    if (rw == O_RDONLY) rwStr = "r";
    else if (O_WRONLY & rw) rwStr = "w";
    else if (O_RDWR & rw) rwStr = "rw";
    return 0;
}

int Logger::sysOpenat(pid_t trace_pid, int &insyscall)
{
    long params[3];
    long eax;
    struct user_regs_struct regs;

    if(insyscall == 0) 
    {
        /* Syscall entry */
        insyscall = 1;
        params[0] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDI,
                        NULL);
        params[1] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RSI,
                        NULL);
        params[2] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDX,
                        NULL);
        printf("data %ld, %ld, %ld\n", params[0], params[1], params[2]);
        std::string msg = "";
        getMsg(trace_pid, params[1], msg);
        std::string flags = "";
        rw2str(params[2], flags);
        printf("[logger] fopen(\"%s\", \"%s\") = BBBBB\n", msg.c_str(), flags.c_str());
    }
    else
    { 
        /* Syscall exit */
        eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * RAX, NULL);
        printf("fopen Write returned with %ld\n", eax);
        // printf("[logger] fopen(%ld, %c, %ld) = %ld\n", params[0], params[1], params[2], eax);
        // printf("[logger] fopen(%lld, %lld, %lld) = %ld\n", regs.rdi, regs.rsi, regs.rdx, eax);
        insyscall = 0;
    }
}

int Logger::sysClose(pid_t trace_pid, int &insyscall)
{
    long params[3];
    long eax;
    struct user_regs_struct regs;

    if(insyscall == 0) 
    {
        /* Syscall entry */
        insyscall = 1;
        params[0] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDI,
                        NULL);
        // printf("data %ld, %ld, %ld\n", params[0], params[1], params[2]);
        // std::string msg = "";
        // getMsg(trace_pid, params[1], msg);
        // std::string flags = "";
        // rw2str(params[2], flags);
        string path_fd = "";
        getFd(trace_pid, params[0], path_fd);
        printf("[logger] close(\"%s\") = close\n", path_fd.c_str());
    }
    else
    { 
        /* Syscall exit */
        eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * RAX, NULL);
        printf("fopen Write returned with %ld\n", eax);
        // printf("[logger] fopen(%ld, %c, %ld) = %ld\n", params[0], params[1], params[2], eax);
        // printf("[logger] fopen(%lld, %lld, %lld) = %ld\n", regs.rdi, regs.rsi, regs.rdx, eax);
        insyscall = 0;
    }
    return 0;
}

int Logger::traceChild(pid_t trace_pid)
{
    int wstatus;
    long orig_eax, eax;
    int insyscall = 0;
    int ret = 0;
    while(waitpid(trace_pid, &wstatus, 0))
    {
        if (WIFEXITED(wstatus)){
            printf("child exits\n");
            return 0;
        }
        else if(WIFSTOPPED(wstatus)){
            orig_eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * ORIG_RAX, NULL);
            // original_rax = ptrace(PTRACE_PEEKUSER, trace_pid, &user_space->regs.orig_rax, NULL);
            // printf("orig_eax %lx %ld\n",  orig_eax, orig_eax);
            switch (orig_eax)
            {
            case -1:
                perror("ptrace PTRACE_PEEKUSER error");
                break;
            case SYS_write:
                printf("SYS_write %ld\n", orig_eax);
                ret = sysWrite(trace_pid, insyscall);
                break;
            case SYS_openat:
                printf("SYS_openat %ld\n", orig_eax); 
                ret = sysOpenat(trace_pid, insyscall);
                break;
            case SYS_close:
                printf("SYS_close %ld\n", orig_eax); 
                ret = sysClose(trace_pid, insyscall);
                break;
            // case SYS_chmod:
            //     printf("SYS_chmod %ld\n", orig_eax); 
            //     ret = sysWrite(trace_pid, insyscall);
            //     break;
            // case SYS_openat:
            //     printf("SYS_openat %ld\n", orig_eax);
            //     ret = sysWrite(trace_pid, insyscall);
            default:
                break;
            }
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