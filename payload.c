// syscalls
long sys_write(long, char *, unsigned long);
int sys_fsync(int);
// libc
long long _strlen(char *);
int _puts(char *str);


_start() {
	_puts("I'm an payload! You are infected!!\n");
}

long sys_write(long fd, char * buf, unsigned long len) {
	long ret;
	__asm__ __volatile__(
		"mov %0, %%rdi		\n\t"
		"mov %1, %%rsi		\n\t"
		"mov %2, %%rdx		\n\t"
		"mov $1, %%rax		\n\t"
		"syscall" : : "g"(fd), "g"(buf), "g"(len));
	__asm__("mov %%rax, %0" : "=r"(ret));
	return ret;
}

int sys_fsync(int fd) {
	long ret;
	__asm__ __volatile__(
		"mov %0, %%rdi		\n\t"
		"mov $74, %%rax		\n\t"
		"syscall" : : "g"(fd));
	__asm__ ("mov %%rax, %0" : "=r"(ret));
	return (int)ret;
}

long long _strlen(char *s) { 
	long long sz;

	for (sz=0;s[sz];sz++);
	return sz;
}

int _puts(char *str) {
	sys_write(1, str, _strlen(str));
	sys_fsync(1);

	return 1;
}
