#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <string>
#include <vector>

struct MSG {   
    std::string command;
    std::string pid;
    std::string user;
    std::string fd;
    std::string type;
    std::string node;
    std::string name;
};

class Logger{
    private:
        std::string m_outputToFile, m_loggerPath;
        int getDirList(std::string path, std::vector<std::string> &dirlist);
        int readFileToVector(std::string filePath, std::vector<std::string> &datas);
        bool isNumber(const std::string& str);
        int createIOFile(std::string outputToFile);
        int traceChild(pid_t pid);
        int getEax(pid_t trace_pid, int &insyscall);
        int m_fdFile;
        int m_fdIO;
    public:
        Logger(std::string outputToFile, std::string loggerPath);
        ~Logger();
        int run(int cmdId, char* argv[]);
};

#endif //__LOGGER_H__