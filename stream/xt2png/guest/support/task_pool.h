#ifndef TASK_POOL_H
#define TASK_POOL_H

#include <functional>
#include <future>
#include <utility>

// extraThreadCount comes from Go (env.pref_extra_threads). Official
// preflate uses that to size the analyze queue. addTask only runs if
// Go returns a non-zero count; one guest instance is not reentrant,
// so the host currently returns 0 and preflate stays on the inline path.
class TaskPool {
public:
	TaskPool() = default;
	~TaskPool() = default;

	template <class F, class... Args>
	auto addTask(F &&f, Args &&...args) -> std::future<typename std::result_of<F(Args...)>::type> {
		using R = typename std::result_of<F(Args...)>::type;
		std::packaged_task<R()> task(std::bind(std::forward<F>(f), std::forward<Args>(args)...));
		std::future<R> res = task.get_future();
		task();
		return res;
	}

	size_t extraThreadCount() const;
};

extern TaskPool globalTaskPool;

#endif
