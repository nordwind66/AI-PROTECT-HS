// A small thread pool with per-job deadlines, used by the rule-set compiler (build time only, never by the runtime).
//
// Why not std::async or a plain parallel-for: Hyperscan offers no way to interrupt hs_compile(). A job that runs longer
// than its deadline is therefore ABANDONED: the caller receives a result with timed_out == true, a replacement worker
// takes over its place and the stuck thread is detached (it ends by itself when the library call returns, or with the
// process). All state shared with the workers lives in shared_ptr objects, so an abandoned thread never touches freed
// memory. A process that abandoned a worker should leave with std::_Exit() (see pool_abandoned_total()).
//
// Threading model: ONE supervisor thread (the caller of submit() / run()) and N workers. Result callbacks run on the
// supervisor thread, so they need no locking and may call submit() to schedule follow-up jobs.
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdio>
#include <deque>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace apg {

struct PoolJob {
    int kind = 0;                     // meaning is private to the caller
    size_t index = 0;                 // caller-defined (entry index, shard number, ...)
    int attempt = 0;                  // caller-defined
    std::vector<size_t> members;      // caller-defined
    double timeout_s = 0;             // <= 0: no deadline
};

struct PoolResult {
    PoolJob job;                      // filled in by the pool
    bool ok = false;
    bool timed_out = false;           // the deadline passed; the job may still be running in an abandoned thread
    bool skipped = false;             // never ran: no worker was left
    int bad_index = -1;               // caller-defined diagnostic (e.g. which expression Hyperscan rejected)
    std::string error;
    std::string blob;                 // caller-defined payload
    double ms = 0;                    // wall time of the job in milliseconds
    size_t bytes = 0;                 // caller-defined size
};

struct PoolStatus {
    size_t queued = 0;                // waiting for a worker
    size_t running = 0;               // being executed right now
    size_t completed = 0;             // results delivered so far
    int abandoned = 0;                // workers given up on because of a deadline
    double oldest_s = 0;              // age of the longest-running job in seconds
    PoolJob oldest;                   // ... and that job
};

// Process-wide number of workers that were abandoned (see the file comment).
inline std::atomic<int>& pool_abandoned_counter() {
    static std::atomic<int> n(0);
    return n;
}
inline int pool_abandoned_total() { return pool_abandoned_counter().load(); }

class JobPool {
public:
    typedef std::function<PoolResult(const PoolJob&)> Executor;

    // `fn` runs on worker threads and must be thread-safe; it must own (shared_ptr) everything it uses because an
    // abandoned worker can outlive the pool. At most `max_abandoned` replacement workers are started.
    JobPool(int workers, Executor fn, int max_abandoned)
        : st_(std::make_shared<Shared>()),
          fn_(std::make_shared<Executor>(std::move(fn))),
          max_abandoned_(max_abandoned),
          abandoned_(0),
          completed_(0) {
        if (workers < 1) workers = 1;
        std::lock_guard<std::mutex> lk(st_->mu);
        try {
            for (int i = 0; i < workers; ++i) spawn_locked();
        } catch (...) {
            if (threads_.empty()) throw;   // not even one worker could be started
            // otherwise: carry on with the workers that exist
        }
    }

    ~JobPool() {
        {
            std::lock_guard<std::mutex> lk(st_->mu);
            st_->stop = true;
            for (size_t i = 0; i < st_->slots.size() && i < threads_.size(); ++i) {
                Slot& s = st_->slots[i];
                if (s.busy && !s.abandoned) {          // still inside a library call: do not wait for it
                    s.abandoned = true;
                    ++abandoned_;
                    pool_abandoned_counter().fetch_add(1);
                    if (threads_[i].joinable()) threads_[i].detach();
                }
            }
        }
        st_->cv_work.notify_all();
        for (std::thread& t : threads_) {
            if (t.joinable()) t.join();
        }
    }

    JobPool(const JobPool&) = delete;
    JobPool& operator=(const JobPool&) = delete;

    // Queues a job. Call it from the thread that calls run() (before run(), or from a result callback).
    void submit(PoolJob job) {
        {
            std::lock_guard<std::mutex> lk(st_->mu);
            st_->queue.push_back(std::move(job));
        }
        st_->cv_work.notify_one();
    }

    // Delivers every result (also those of jobs submitted by the callback) to on_result(); returns when nothing is
    // queued or running any more. on_tick(status) is called about every tick_s seconds (<= 0: never).
    void run(const std::function<void(PoolResult&)>& on_result, const std::function<void(const PoolStatus&)>& on_tick,
             double tick_s) {
        Clock::time_point last_tick = Clock::now();
        for (;;) {
            std::vector<PoolResult> ready;
            bool idle = false;
            {
                std::unique_lock<std::mutex> lk(st_->mu);
                while (!st_->done.empty()) {
                    ready.push_back(std::move(st_->done.front()));
                    st_->done.pop_front();
                }
                // jobs that run longer than their deadline are given up
                const Clock::time_point now = Clock::now();
                int to_spawn = 0;
                for (size_t i = 0; i < st_->slots.size(); ++i) {
                    Slot& s = st_->slots[i];
                    if (!s.busy || s.abandoned || s.job.timeout_s <= 0) continue;
                    const double age = std::chrono::duration<double>(now - s.start).count();
                    if (age <= s.job.timeout_s) continue;
                    s.abandoned = true;
                    if (i < threads_.size() && threads_[i].joinable()) threads_[i].detach();
                    ++abandoned_;
                    pool_abandoned_counter().fetch_add(1);
                    PoolResult r;
                    r.job = s.job;
                    r.timed_out = true;
                    r.ms = age * 1000.0;
                    r.error = "no result after " + seconds_text(s.job.timeout_s) + " (gave up)";
                    ready.push_back(std::move(r));
                    if (abandoned_ <= max_abandoned_) ++to_spawn;
                }
                for (int k = 0; k < to_spawn; ++k) {
                    try {
                        spawn_locked();
                    } catch (...) {
                        break;
                    }
                }
                // no worker left: the queue can never be served
                size_t live = 0;
                size_t running = 0;
                for (const Slot& s : st_->slots) {
                    if (!s.abandoned) ++live;
                    if (s.busy && !s.abandoned) ++running;
                }
                if (live == 0) {
                    while (!st_->queue.empty()) {
                        PoolResult r;
                        r.job = std::move(st_->queue.front());
                        st_->queue.pop_front();
                        r.skipped = true;
                        r.error = "no worker left (too many jobs exceeded their deadline)";
                        ready.push_back(std::move(r));
                    }
                }
                idle = ready.empty() && st_->queue.empty() && running == 0;
                if (!idle && ready.empty()) st_->cv_done.wait_for(lk, std::chrono::milliseconds(200));
            }
            for (PoolResult& r : ready) {
                ++completed_;
                on_result(r);
            }
            if (idle) return;
            if (tick_s > 0 && on_tick &&
                std::chrono::duration<double>(Clock::now() - last_tick).count() >= tick_s) {
                last_tick = Clock::now();
                on_tick(status());
            }
        }
    }

    int abandoned() const { return abandoned_; }

    PoolStatus status() const {
        PoolStatus out;
        std::lock_guard<std::mutex> lk(st_->mu);
        const Clock::time_point now = Clock::now();
        out.queued = st_->queue.size();
        out.completed = completed_;
        out.abandoned = abandoned_;
        for (const Slot& s : st_->slots) {
            if (!s.busy || s.abandoned) continue;
            ++out.running;
            const double age = std::chrono::duration<double>(now - s.start).count();
            if (age >= out.oldest_s) {
                out.oldest_s = age;
                out.oldest = s.job;
            }
        }
        return out;
    }

private:
    typedef std::chrono::steady_clock Clock;

    struct Slot {
        bool busy = false;
        bool abandoned = false;
        Clock::time_point start;
        PoolJob job;
    };
    struct Shared {
        std::mutex mu;
        std::condition_variable cv_work;    // workers wait for jobs
        std::condition_variable cv_done;    // the supervisor waits for results
        std::deque<PoolJob> queue;
        std::deque<PoolResult> done;
        std::vector<Slot> slots;            // one per worker thread ever started (index == worker id)
        bool stop = false;
    };

    static std::string seconds_text(double s) {
        char buf[48];
        std::snprintf(buf, sizeof(buf), "%.0f s", s);
        return std::string(buf);
    }

    // The mutex of st_ must be held. Starts one more worker.
    void spawn_locked() {
        const size_t id = st_->slots.size();
        st_->slots.emplace_back();
        try {
            threads_.emplace_back(&JobPool::worker_main, st_, fn_, id);
        } catch (...) {
            st_->slots.pop_back();
            throw;
        }
    }

    static void worker_main(std::shared_ptr<Shared> st, std::shared_ptr<Executor> fn, size_t id) {
        for (;;) {
            PoolJob job;
            {
                std::unique_lock<std::mutex> lk(st->mu);
                st->cv_work.wait(lk, [&st, id] { return st->stop || st->slots[id].abandoned || !st->queue.empty(); });
                if (st->stop || st->slots[id].abandoned) return;
                job = std::move(st->queue.front());
                st->queue.pop_front();
                Slot& s = st->slots[id];
                s.busy = true;
                s.start = Clock::now();
                s.job = job;
            }
            PoolResult r;
            try {
                r = (*fn)(job);
            } catch (const std::exception& e) {
                r = PoolResult();
                r.error = std::string("internal error: ") + e.what();
            } catch (...) {
                r = PoolResult();
                r.error = "internal error";
            }
            r.job = job;
            {
                std::lock_guard<std::mutex> lk(st->mu);
                Slot& s = st->slots[id];
                s.busy = false;
                if (s.abandoned) return;            // the supervisor already gave up on this job
                st->done.push_back(std::move(r));
            }
            st->cv_done.notify_one();
        }
    }

    std::shared_ptr<Shared> st_;
    std::shared_ptr<Executor> fn_;
    std::vector<std::thread> threads_;      // threads_[i] runs slots[i]; touched by the supervisor thread only
    int max_abandoned_;
    int abandoned_;
    size_t completed_;
};

}  // namespace apg
