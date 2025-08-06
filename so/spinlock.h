#pragma once
#include <signal.h>
#include <thread>
#include "Ucom.h"

// 获取当前lwp的pid
static inline pid_t get_tid()
{
    return static_cast<pid_t>(::syscall(SYS_gettid));
}


// 跨进程自旋锁
class SpinLock
{
private:
    time_t m_time;
    volatile long *m_lock;

public:
    SpinLock(volatile long *lock) { m_lock = lock; }

    void lock()
    {
        m_time = time(nullptr);
        pid_t tid = get_tid();
        pid_t pid_occupy = *m_lock;
        pid_t last_pid_occupy = 0;
        bool print_warning = false;
        while ((pid_occupy = __sync_val_compare_and_swap(m_lock, 0, tid)))
        {
            if (pid_occupy != last_pid_occupy)
            {
                last_pid_occupy = pid_occupy;
                m_time = time(nullptr);
            }

            if (time(nullptr) - m_time > 4 && !print_warning)
            {
                /**
                 * 前置条件：
                 * 任何代码对自旋锁的占用，不得超过5s
                 * 否则就是代码设计问题
                 */
                print_warning = true;
                pr_warn("SpinLock::lock occupied by pid %d over 5 seconds, "
                    "please check the state of that process, "
                    "and kill it manually if necessary", pid_occupy);
                Trace::pstack();
            }
            /**
             * Yield to allow other threads to run
             * 在同一个CPU上自旋锁的抢占会导致死锁，
             * 因此这里使用yield让出CPU时间片
             */
            std::this_thread::yield();
        }
    }

    bool try_lock()
    {
        pid_t tid = get_tid();
        return __sync_bool_compare_and_swap(m_lock, 0, tid);
    }

    void unlock()
    {
        pid_t tid = get_tid();
        if (tid != *m_lock)
            return;

        __sync_lock_release(m_lock);
        /**
         * 开发期间断言保证前置条件
         * 任何代码对自旋锁的占用，不得超过5s
         */
        assert(time(nullptr) - m_time < 5);
    }

    static bool check_consistency(volatile long *lock)
    {
        pid_t pid_occupy = *lock;
        if (pid_occupy == 0)
            return true;
        if (kill(pid_occupy, 0) == 0)
            return true;
        return *lock == 0;
    }
};

class SpinLockGuard
{
private:
    SpinLock *m_lock;

public:
    SpinLockGuard(SpinLock *lock)
    {
        m_lock = lock;
        m_lock->lock();
    }
    ~SpinLockGuard()
    {
        m_lock->unlock();
    }
};