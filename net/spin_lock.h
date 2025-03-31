#ifndef MY_SPINLOCK_H
#define MY_SPINLOCK_H

#include <atomic>

struct MySpinLock {
	inline void lock() {
		bool expected = false;
		while(!sem.compare_exchange_strong(expected, true, std::memory_order_acq_rel));
	}
	inline void unlock() {
		sem.store(false, std::memory_order_release);
	}
	std::atomic<bool> sem = false;
};

#endif