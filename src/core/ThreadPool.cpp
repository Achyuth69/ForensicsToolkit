#include "ThreadPool.h"
#include <QThread>

namespace Forensic::Core {

ForensicTask::ForensicTask(std::function<void()> fn, std::function<void()> done)
    : m_fn(std::move(fn)), m_done(std::move(done))
{
    setAutoDelete(true);
}

void ForensicTask::run() {
    if (m_fn)   m_fn();
    if (m_done) m_done();
}

// ─── ThreadPool ───────────────────────────────────────────────────────────────
ThreadPool& ThreadPool::instance() {
    static ThreadPool inst;
    return inst;
}

ThreadPool::ThreadPool() {
    int cores = QThread::idealThreadCount();
    m_pool.setMaxThreadCount(qMax(2, cores));
}

void ThreadPool::submit(std::function<void()> fn, std::function<void()> done) {
    auto *task = new ForensicTask(std::move(fn), std::move(done));
    m_pool.start(task);
}

void ThreadPool::setMaxThreads(int n) {
    m_pool.setMaxThreadCount(n);
}

int ThreadPool::activeThreadCount() const {
    return m_pool.activeThreadCount();
}

void ThreadPool::waitForAll() {
    m_pool.waitForDone();
}

} // namespace Forensic::Core
