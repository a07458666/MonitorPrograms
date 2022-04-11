#include <stdio.h>
#include <vector>
#include <string>
#include <cstring>
#include <getopt.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PATH_MAX 1024
int GetOpt(int argc, char* argv[], 
        std::string &outputToFile,
        std::string &loggerPath)
{
    int flags, opt;
    int nsecs, tfnd;
    std::string filter;
    nsecs = 0;
    tfnd = 0;
    while ((opt = getopt(argc, argv, "o:p:")) != -1) {
        switch (opt) {
        case 'o':
            // print output to file, print to "stderr" if no file specified
            outputToFile = optarg;
            // dlopen(outputToFile.c_str(), RTLD_LAZY);
            break;
        case 'p':
            // set the path to logger.so, default = ./logger.so
            loggerPath = optarg;
            break;
        default: /* '?' */
            fprintf(stderr, "Usage: %s [-o file] [-p sopath] [--] cmd [cmd args ...]\n-p: set the path to logger.so, default = ./logger.so\n-o: print output to file, print to 'stderr' if no file specified\n--: separate the arguments for logger and for the command\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}

int GetCmd(int argc, char* argv[])
{
    int cmdId = -1;
    if (argc >= 2 && argv[1][0] != '-') cmdId = 1;
    for (int i = 0;i < argc; i++)
    {
        if (strcmp(argv[i], "--") == 0)
        {
            if (i + 1 < argc)
            {
                cmdId = i + 1;
                break;
            }
            else
            {
                fprintf(stderr, "Usage: %s [-o file] [-p sopath] [--] cmd [cmd args ...]\n-p: set the path to logger.so, default = ./logger.so\n-o: print output to file, print to 'stderr' if no file specified\n--: separate the arguments for logger and for the command\n", argv[0]);
                exit(EXIT_FAILURE);
            }
        }
    }    
    return cmdId;
}

int createIOFile(std::string outputToFile){
    int fdIO = 1;
    int fdErr = 2;
    int fdFile = open(outputToFile.c_str(), O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
    if (fdFile != -1)
    {
        // dup2(fdFile, fdIO);
        dup2(fdFile, fdErr);
    }
    return fdFile;
}

int main(int argc, char* argv[]){
    std::string outputToFile = "", loggerPath = "./logger.so";
    if (argc == 1)
    {
        fprintf(stderr, "no command given.\n");
        exit(EXIT_FAILURE);
    }
    int cmdId = GetCmd(argc, argv);
    if (cmdId != 1){
        int err = GetOpt(argc, argv, outputToFile, loggerPath);
        if (err == -1) return err;    
    }

    if (outputToFile != "")
    {
        int fdFile = createIOFile(outputToFile);
    }

    pid_t pid; 

    if ((pid = fork()) < 0)
    {
        perror("fork fail");
    }
    else if (pid == 0)
    {
        //child
        // printf("[child]pid %d getpid %d\n", pid, getpid());
        char path[1024];
        sprintf(path, "LD_PRELOAD=%s", loggerPath.c_str());
        char * const envp[] = {path,  NULL};
        execvpe(argv[cmdId], &argv[cmdId], envp);
    }
    else
    {
        //parent
        // printf("[parent]child pid %d getpid %d\n", pid, getpid());
        // int ret = traceChild(pid);
        int wstatus;
        while(waitpid(pid, &wstatus, 0))
        {
            if (WIFEXITED(wstatus)){
                // printf("child exits\n");
                return 0;
            }
        }
    }
    return 0;
}