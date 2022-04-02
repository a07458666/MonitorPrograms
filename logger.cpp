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
            printf("child pid %d getpid %d\n", pid, getpid());
            execvp(argv[cmdId], &argv[cmdId]);
        }
        else
        {
            //parent
            printf("parent pid %d getpid %d\n", pid, getpid());
            int wstatus;
            while(waitpid(pid, &wstatus, WNOHANG) != -1)
            {
                sleep(1);
                printf("run\n");
            }
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << "run() " << e.what() << '\n';
    }     
    return 0;
}