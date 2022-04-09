#include "Logger.h"

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
// #include <sys/user.h>

#define ERR -1

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
    for (int i = 0; i < str.length(); i++) {
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

int Logger::getEax(pid_t trace_pid, int &insyscall)
{
    long params[3];
    long eax;

    if(insyscall == 0) 
    {
        /* Syscall entry */
        insyscall = 1;
        params[0] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RBX,
                        NULL);
        params[1] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RCX,
                        NULL);
        params[2] = ptrace(PTRACE_PEEKUSER,
                        trace_pid, 8 * RDX,
                        NULL);
        printf("Write called with %ld, %lx, %ld\n", params[0], params[1], params[2]);
    }
    else
    { 
        /* Syscall exit */
        eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * RAX, NULL);
        printf("Write returned with %ld\n", eax);
        insyscall = 0;
    }
}


int Logger::traceChild(pid_t trace_pid)
{
    int wstatus;
    long orig_eax, eax;
    // long original_rax;
    int insyscall = 0;
    int insyscall_open = 0;
    int insyscall_close = 0;

    int ret = 0;
    // struct user* user_space = (struct user*)0;

    // ptrace(PTRACE_ATTACH, trace_pid, NULL, NULL);
    while(waitpid(trace_pid, &wstatus, 0))
    {
        if (WIFEXITED(wstatus)){
            printf("child exits\n");
            return 0;
        }
        else if(WIFSTOPPED(wstatus)){
            orig_eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * ORIG_RAX, NULL);
            // original_rax = ptrace(PTRACE_PEEKUSER, trace_pid, &user_space->regs.orig_rax, NULL);
            printf("orig_eax %ld\n", orig_eax);
            switch (orig_eax)
            {
            case -1:
                printf("%s\n", strerror(errno));
                break;
            case SYS_write:
                printf("SYS_write %ld\n", orig_eax);
                ret = getEax(trace_pid, insyscall);
                break;
            case SYS_open:
                printf("SYS_open %ld\n", orig_eax); 
                ret = getEax(trace_pid, insyscall_open);
                break;
            case SYS_close:
                printf("SYS_close %ld\n", orig_eax); 
                ret = getEax(trace_pid, insyscall_close);
                break;
            default:
                break;
            }
            // if(orig_eax == SYS_write) {
            //     if(insyscall == 0) 
            //     {
            //         /* Syscall entry */
            //         insyscall = 1;
            //         params[0] = ptrace(PTRACE_PEEKUSER,
            //                         trace_pid, 8 * RBX,
            //                         NULL);
            //         params[1] = ptrace(PTRACE_PEEKUSER,
            //                         trace_pid, 8 * RCX,
            //                         NULL);
            //         params[2] = ptrace(PTRACE_PEEKUSER,
            //                         trace_pid, 8 * RDX,
            //                         NULL);
            //         printf("Write called with %ld, %ld, %ld\n", params[0], params[1], params[2]);
            //     }
            //     else
            //     { 
            //         /* Syscall exit */
            //         eax = ptrace(PTRACE_PEEKUSER, trace_pid, 8 * RAX, NULL);
            //         printf("Write returned with %ld\n", eax);
            //         insyscall = 0;
            //     }
            // }
            ptrace(PTRACE_SYSCALL, trace_pid, NULL, NULL);
            // ptrace(PTRACE_CONT, trace_pid, NULL, NULL);
        }
    }
    // ptrace(PTRACE_CONT, trace_pid, NULL, NULL);
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