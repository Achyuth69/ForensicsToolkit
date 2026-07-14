#pragma once
#include <QObject>
#include <QThreadPool>
#include <QRunnable>
#include <functional>
#include <atomic>

namespace Forensic::Core {

class ForensicTask : public QRunnable {
public:
    explicit ForensicTask(std::function<void()> fn, std::function<void()> done = nullptr);
    void run() override;

private:
    std::function<void()> m_fn;
    std::function<void()> m_done;
};

class ThreadPool : public QObject {
    Q_OBJECT
public:
    static ThreadPool& instance();

    void submit(std::function<void()> fn, std::function<void()> done = nullptr);
    void setMaxThreads(int n);
    int  activeThreadCount() const;
    void waitForAll();

private:
    ThreadPool();
    QThreadPool m_pool;
};

} // namespace Forensic::Core
