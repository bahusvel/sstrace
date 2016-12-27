#include <sys/syscall.h>

void syscall1(long call, long param) {
  asm volatile("syscall" : : "a"(call), "D"(param));
}

void main() { syscall1(SYS_exit, 10); }
