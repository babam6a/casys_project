#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <asm/prctl.h>
#include <sys/syscall.h>

#define BITMASK(SHIFT, CNT) (((1ul << (CNT)) - 1) << (SHIFT))
#define ROUND_UP(X, STEP) (((X) + (STEP) - 1) / (STEP) * (STEP))

/* Page offset (bits 0:12). */
#define PGSHIFT 0                          /* Index of first offset bit. */
#define PGBITS  12                         /* Number of offset bits. */
#define PGSIZE  (1 << PGBITS)              /* Bytes in a page. */
#define PGMASK  BITMASK(PGSHIFT, PGBITS)   /* Page offset bits (0:12). */
#define pg_ofs(va) ((uint64_t) (va) & PGMASK)

/* global var */
static sigjmp_buf env;
struct sigaction act;
uint64_t stack;

void print_mapping_info(uint64_t base_addr, uint64_t ofs, uint64_t size) {
	char message[1024];
	snprintf(message, sizeof(message), "Loader mapped memory at [base address]: %lx, [file offset]: %lx, [size]: %lx\n",
	base_addr, ofs, size);
	write(STDERR_FILENO, message, strlen(message));
}

int set_flags(uint32_t auth) {
	int flags = 0;

	if ((auth & PF_R) != 0)
		flags |= PROT_READ;
	if ((auth & PF_W) != 0)
		flags |= PROT_WRITE;
	if ((auth & PF_X) != 0)
		flags |= PROT_EXEC;
	
	return flags;
}

static bool validate_segment (const Elf64_Phdr* phdr, FILE* file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	// if (phdr->p_offset > file_size)
	// 	return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

void *load_segment (FILE *file, uint64_t section_ofs, uint64_t code_size, Elf64_Phdr *phdrs, int load_phdr_num) {
	int map_flag = MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;
	int protect_flag = PROT_READ | PROT_WRITE;

	/* mmap page */
	void *upage = (void *)phdrs[0].p_vaddr;
	void *kpage = (void *)mmap((void *)upage, code_size, protect_flag, map_flag, -1, 0);
	if (kpage == MAP_FAILED) {
		printf("mmap failed!\n");
		return false;
	}

	print_mapping_info((uint64_t)upage, 0, code_size);

	for (int i = 0; i < load_phdr_num; i++) {
		uint64_t load_addr = phdrs[i].p_vaddr;
		uint32_t size = phdrs[i].p_filesz;
		uint32_t ofs = phdrs[i].p_offset;
		
		fseek(file, ofs, SEEK_SET);

		if (fread ((void *)load_addr, 1, size, file) != size) {
			printf("memcpy error\n");
			goto error;
		}

		int flags = set_flags(phdrs[i].p_flags);
		load_addr = load_addr & ~PGMASK;
		size = size + (load_addr & (PGSIZE - 1));
		
		if (mprotect((void *)load_addr, size, flags) == -1) {
			printf("mprotect error\n");
			goto error;
		}
	}
	return kpage;

error:
	munmap(kpage, code_size);
	return NULL;
}

bool check_elf(Elf64_Ehdr *ehdr) {
	if (memcmp (ehdr-> e_ident, "\177ELF\2\1\1", 7)
		|| ehdr-> e_type != 2 // limit as EXE
		|| ehdr-> e_machine != 0x3E // amd64
		|| ehdr-> e_version != 1
		|| ehdr -> e_phentsize != sizeof (Elf64_Phdr)
		|| ehdr -> e_phnum > 1024)
		return false;
	return true;
}

Elf64_Phdr *load_phdr(FILE *file, Elf64_Ehdr *ehdr, uint64_t *load_phdr_num) {
	int64_t file_ofs = ehdr-> e_phoff;

	Elf64_Phdr *phdrs = (Elf64_Phdr *)calloc(sizeof(Elf64_Phdr), ehdr-> e_phnum);
	if (phdrs == NULL) {
		printf("phdr calloc error\n");
		return NULL;
	}

	*load_phdr_num = 0;

	for (int i = 0; i < ehdr-> e_phnum; i++) {
		Elf64_Phdr phdr = phdrs[i];

        fseek(file, file_ofs, SEEK_SET);

		if (fread (&phdr, 1, sizeof(phdr), file) != sizeof(phdr)) {
			printf("phdr read error\n");
			goto error;
		}

		file_ofs += sizeof(phdr);

		switch (phdr.p_type) {
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					phdrs[*load_phdr_num] = phdr;
					*load_phdr_num = *load_phdr_num + 1;
				}
				else {
					printf("valid segment error\n");
					goto error;
				}
				break;
			case PT_SHLIB:
				goto error;
			default:
				/* Ignore this segment. */
				break;
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_DYNAMIC:
			case PT_INTERP:
				break;
		}
	}
	return phdrs;

error:
	free(phdrs);
	return NULL;
}

uint64_t write_aux_val(uint64_t rsp, uint64_t var, uint64_t val) {
	uint64_t *stack_pointer = (uint64_t *)rsp;

	/* stack top to bottom */
	*stack_pointer = var;
	stack_pointer++;
	
	*stack_pointer = val;
	stack_pointer++;

	return (uint64_t)stack_pointer;
}

void *setup_stack(int argc, char **argv, char **envp, Elf64_Ehdr *ehdr, void *kpage) {
	int stack_flag = MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK;
	int priority_flag = PROT_READ | PROT_WRITE;
	uint64_t stack_size = PGSIZE * 64; // too many environments..

	stack = (uint64_t)mmap(0, stack_size, priority_flag, stack_flag, -1 , 0);
	if ((void *)stack == MAP_FAILED) {
		printf("stack mmap failed\n");
		goto error;
	}
	
	print_mapping_info(stack, 0, stack_size);

	/* start from top addr & align stack */
	uint64_t stack_pointer = (stack + stack_size) & (~15);

	/* get argv, envp numbers */
	int argv_num = 0;
	int envp_num = 0;
	for (argv_num; ; argv_num++) {
		if (argv[argv_num] == NULL)
			break;
	}

	for (envp_num; ; envp_num++) {
		if (envp[envp_num] == NULL)
			break;
	}

	/* copy envp */
	for (int i = envp_num - 1; i >= 0; i--) {
		if (envp[i] == NULL)
			break;
		
		int len = strlen(envp[i]);
		stack_pointer -= (len + 1); // consider '\0'
		memcpy((void *)stack_pointer, envp[i], len + 1);
	}

	/* copy argv */
	for (int i = argv_num - 1; i >= 1; i--) {
		int len = strlen(argv[i]);
		stack_pointer -= (len + 1); // consider '\0'
		memcpy((void *)stack_pointer, argv[i], len + 1);
	}

	/* Unspecified */
	stack_pointer = stack_pointer & (~(uint64_t)15);
	stack_pointer -= 8 * 38; // Auxiliary vector
	stack_pointer -= ((envp_num + 1) * 8 + (argv_num + 1) * 8); //argv & envp
	stack_pointer -= 8; // argc
	stack_pointer = stack_pointer & (~15); // align

	void *rsp = (void *)stack_pointer;

	/* argc */
	*(uint64_t *)stack_pointer = (uint64_t)(argc - 1);
	stack_pointer += 8;

	/* copy argv pointers */
	for (int i = 1; i < argv_num; i++) {
		memcpy((void *)stack_pointer, &argv[i], 8);
		stack_pointer += 8;
	}

	/* 0 padding */
	memset((void *)stack_pointer, 0, 8);
	stack_pointer += 8;

	/* copy envp pointers */
	for (int i = 0; i < envp_num - 1; i++) {
		memcpy((void *)stack_pointer, &envp[i], 8);
		stack_pointer += 8;
	}

	/* 0 padding */
	memset((void *)stack_pointer, 0, 8);
	stack_pointer += 8;

	/* Auxiliary vector entries */
	stack_pointer = write_aux_val(stack_pointer, AT_EXECFN, (uint64_t)argv[0]);
	stack_pointer = write_aux_val(stack_pointer, AT_HWCAP2, (uint64_t)getauxval(AT_HWCAP2));
	stack_pointer = write_aux_val(stack_pointer, AT_RANDOM, (uint64_t)getauxval(AT_RANDOM));
	stack_pointer = write_aux_val(stack_pointer, AT_SECURE, (uint64_t)getauxval(AT_SECURE));
	stack_pointer = write_aux_val(stack_pointer, AT_EGID, (uint64_t)getauxval(AT_EGID));
	stack_pointer = write_aux_val(stack_pointer, AT_GID, (uint64_t)getauxval(AT_GID));
	stack_pointer = write_aux_val(stack_pointer, AT_EUID, (uint64_t)getauxval(AT_EUID));
	stack_pointer = write_aux_val(stack_pointer, AT_UID, (uint64_t)getauxval(AT_UID));
	stack_pointer = write_aux_val(stack_pointer, AT_ENTRY, (uint64_t)ehdr-> e_entry);
	stack_pointer = write_aux_val(stack_pointer, AT_FLAGS, (uint64_t)getauxval(AT_FLAGS));
	stack_pointer = write_aux_val(stack_pointer, AT_BASE, (uint64_t)0); // static, no interpreter
	stack_pointer = write_aux_val(stack_pointer, AT_PHNUM, (uint64_t)ehdr-> e_phnum);
	stack_pointer = write_aux_val(stack_pointer, AT_PHENT, (uint64_t)ehdr-> e_phentsize);
	stack_pointer = write_aux_val(stack_pointer, AT_PHDR, (uint64_t)(kpage + ehdr-> e_phoff));
	stack_pointer = write_aux_val(stack_pointer, AT_CLKTCK, (uint64_t)getauxval(AT_CLKTCK));
	stack_pointer = write_aux_val(stack_pointer, AT_PAGESZ, (uint64_t)getauxval(AT_PAGESZ));
	stack_pointer = write_aux_val(stack_pointer, AT_HWCAP, (uint64_t)getauxval(AT_HWCAP));
	stack_pointer = write_aux_val(stack_pointer, AT_SYSINFO_EHDR, (uint64_t)getauxval(AT_SYSINFO_EHDR));
	// printf("stack_pointer after auxiliary vector: %lx\n",stack_pointer);

	/* Null auxiliary vector entry */
	memset((void *)stack_pointer, 0, 8);
	stack_pointer += 8;

	// printf("stack initialization completed\n");
	return rsp;

error: 
	return NULL;
}

bool check_itself(char *exec_name, char *file_name) {
	char *path1 = realpath(exec_name, NULL);
	char *path2 = realpath(file_name, NULL);

	if (strncmp(path1, path2, strlen(path2)) != 0)
		return false;
	return true;
}

void return_to_loader(int sig, siginfo_t *info, void *unused) {
	if (sig != SIGUSR1)
		exit(0);

	siglongjmp(env, 1);
}

int main(int argc, char** argv, char **envp) {
	char* file_name;
	FILE *file;
	Elf64_Ehdr ehdr;
	Elf64_Phdr *phdrs;
	
	for (int i = 1; i < argc; i++) {
		file_name = argv[i];

		if (file_name == NULL) {
			printf("should have file name or path\n");
			goto error;
		}

		/* check if loading program is the loader itself */
		if (check_itself(argv[0], file_name)) {
			printf("You cannot load loader\n");
			goto error;
		}

		file = fopen(file_name, "rb");
		if (file == NULL) {
			printf ("load: %s: open failed\n", file_name);
			goto error;
		}
		
		/* Read and verify executable header. */
		if ((fread(&ehdr, 1, sizeof(ehdr), file) != sizeof(ehdr)) || !check_elf(&ehdr)) {
			printf("load_ehdr error\n");
			goto file_error;
		}

		/* read and save phdrs */
		uint64_t load_phdr_num = 0;
		phdrs = load_phdr(file, &ehdr, &load_phdr_num);
		if (phdrs == NULL) {
			printf("load_phdr error\n");
			goto file_error;
		}

		uint64_t code_size = phdrs[load_phdr_num - 1].p_vaddr + phdrs[load_phdr_num - 1].p_memsz - (phdrs[0].p_vaddr & ~PGSIZE);

		/* load segments */
		uint64_t section_ofs = ehdr.e_phoff + (ehdr.e_phentsize * ehdr.e_phnum);
		void *kpage = load_segment(file, section_ofs, code_size, phdrs, load_phdr_num);
		if (kpage == NULL) {
			printf("load_segment error\n");
			goto load_error;
		}

		/* Set up stack. */
		void *rsp = setup_stack(argc, argv, envp, &ehdr, kpage);
		if (rsp == NULL) {
			printf("setup_stack failed\n");
			goto file_error;
		}

		fclose(file);
		uint64_t fs_addr;
		if (sigsetjmp(env, 1) == 0) {
			act.sa_flags = SA_SIGINFO;
			act.sa_sigaction = return_to_loader;
			sigemptyset(&act.sa_mask);
			sigaction(SIGUSR1, &act, NULL);

			/* setjmp already saved necessary registers.
			we just save fs base address */
			syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_addr);

			/* Start new thread */
			__asm __volatile(
				"xor %%rax, %%rax\n\t"
				"xor %%rbx, %%rbx\n\t"
				"xor %%rcx, %%rcx\n\t"
				"xor %%rdx, %%rdx\n\t"
				"xor %%rsi, %%rsi\n\t"
				"xor %%rdi, %%rdi\n\t"
				"xor %%r8, %%r8\n\t"
				"xor %%r9, %%r9\n\t"
				"xor %%r10, %%r10\n\t"
				"xor %%r11, %%r11\n\t"
				"xor %%r12, %%r12\n\t"
				"xor %%r13, %%r13\n\t"
				"xor %%r14, %%r14\n\t"
				"xor %%r15, %%r15\n\t"
				: : :
			);
			__asm __volatile(
				"movq %0, %%rsp\n\t"
				"movq %%rsp, %%rbp\n\t"
				"xor %%rdx, %%rdx\n\t" 
				"jmp %1"
				: : "a" (rsp),"b" (ehdr.e_entry) :
			);
		}
		/* reload fs base address */
		syscall(SYS_arch_prctl, ARCH_SET_FS, fs_addr);

		/* clean up */
		free(phdrs);
		if ((munmap(kpage, code_size) != 0)) {
			printf("error while unmap loaded data!\n");
			goto error;
		}
		if ((munmap((void *)stack, PGSIZE * 64) != 0)) {
			printf("error while unmap loaded stack!\n");
			goto error;
		}
	}

	return 0;

load_error:
	free(phdrs);
file_error:
    fclose(file);
error:
    exit(0);
}