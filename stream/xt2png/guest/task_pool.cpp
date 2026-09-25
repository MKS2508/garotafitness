#include "task_pool.h"

size_t TaskPool::extraThreadCount() const { return 0; }

TaskPool globalTaskPool;
