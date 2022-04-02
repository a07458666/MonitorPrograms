#include <stdio.h>
#include <vector>
#include <string>
#include <cstring>
#include <getopt.h>

#include "logger.h"

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

int main(int argc, char* argv[]){
    std::string outputToFile = "", loggerPath = "";
    if (argc == 1)
    {
        printf("no command given.\n");
        exit(EXIT_FAILURE);
    }
    int cmdId = GetCmd(argc, argv);
    if (cmdId != 1){
        int err = GetOpt(argc, argv, outputToFile, loggerPath);
        if (err == -1) return err;    
    }
    Logger logger(outputToFile, loggerPath);
    logger.run(cmdId, argv);
    return 0;
}