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
        int sysRead(pid_t trace_pid, std::string &msg);
        int sysChmod(pid_t trace_pid, std::string &msg);
        int sysCreat(pid_t trace_pid, std::string &msg);
        int sysChown(pid_t trace_pid, std::string &msg);
        int sysRename(pid_t trace_pid, std::string &msg);
        int sysWrite(pid_t trace_pid, std::string &msg);
        int sysOpenat(pid_t trace_pid, std::string &msg);
        int sysClose(pid_t trace_pid, std::string &msg);
        int sysRemove(pid_t trace_pid, std::string &msg);
        void getMsg(pid_t pid, long addr, int len, std::string &msg);
        void getMsg(pid_t pid, long addr, std::string &msg);
        void getRealPath(pid_t pid, long addr, std::string &msg);
        int getFd(pid_t pid, int fd, std::string &link);
        int getLink(std::string path, std::string &link);
        int rw2str(long rw, std::string &rwStr);
        int m_fdFile;
        int m_fdIO;
        int m_insyscall;
    public:
        Logger(std::string outputToFile, std::string loggerPath);
        ~Logger();
        int run(int cmdId, char* argv[]);
};

#endif //__LOGGER_H__