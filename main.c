#include <stdio.h>
#include <xmmintrin.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <setjmp.h>
#include <sys/auxv.h>
#include <asm/prctl.h>
#include <sys/prctl.h>

#include "argument_manager.h"
#include "read_elf.h"
#include "ehdr.h"
#include "phdr.h"
#include "shdr.h"

#define NEW_AUX_ENT(id, val) \
	do { \
		*elf_info++ = id; \
		*elf_info++ = val; \
} while (0)
#define STACK_ADD(sp, items) ((elf_addr_t __user *)(sp) + (items))

const char *key_to_flags = "Key to Flags:\n"
"  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),\n"
"  L (link order), O (extra OS processing required), G (group), T (TLS),\n"
"  C (compressed), x (unknown), o (OS specific), E (exclude),\n"
"  l (large), p (processor specific)\n";

elf_file_t *hdl;
jmp_buf buffer;


void* find_sym(const char* name, Elf64_Shdr* shdr, const char* strings, 
               const char* src, char* dst)
{
    Elf64_Sym* syms = (Elf64_Sym*)(src + shdr->sh_offset);
    int i;
    for(i = 0; i < shdr->sh_size / sizeof(Elf64_Sym); i += 1) {
        printf("%s\n", strings + syms[i].st_name);
        if (strcmp(name, strings + syms[i].st_name) == 0) {
            return dst + syms[i].st_value;
        }
    }
    return NULL;
}


    /*This function loads the section table string table into memory
    and returns a pointer to the start of the string table*/
char* get_sectionHeader_string_table(Elf64_Ehdr *hdr)
{   //shstrndx is the index of the section in the section table
    int index=  hdl->ehdr64->e_shstrndx;
    //This gets the section that stores the string table
    const Elf64_Shdr* shstr = &(hdl->shdr64)[index];
    //The offset of the section in the file on the disk
    Elf64_Off strtab_offset = shstr->sh_offset;

    /*So far only the headers were loaded into memory, now we 
    need to load the string table section itself into memory,
    //to start reading from the appropriate section*/
    fseek(hdl->file,strtab_offset, SEEK_SET); 
    char * String_Table = malloc(sizeof(char)*shstr->sh_size);
    fread(String_Table, sizeof(char),shstr->sh_size, hdl->file);

    return String_Table;
}

/* Display the ELF file header */
static void dump_elf_file_header(Elf64_Ehdr *ehdr)
{
    printf("ELF HEADER:\n");
    printf("  Magic:   ");
    unsigned int i;
    for (i = 0; i < EI_NIDENT; i++)
        printf("%02x ", ehdr->e_ident[i]);
    printf("\n");
    printf("  %-35s%s\n", "Class:", ehdr_get_class(ehdr->e_ident[EI_CLASS]));
    printf("  %-35s%s\n", "Data:", ehdr_get_data(ehdr->e_ident[EI_DATA]));
    printf("  %-35s%d %s\n", "Version:", ehdr->e_ident[EI_VERSION], 
           ehdr_get_version(ehdr->e_ident[EI_VERSION]));
    printf("  %-35s%s\n", "OS/ABI:", ehdr_get_osabi(ehdr->e_ident[EI_OSABI]));
    printf("  %-35s%d\n", "ABI Version:", ehdr->e_ident[EI_ABIVERSION]);
    printf("  %-35s%s\n", "Type:", ehdr_get_type(ehdr->e_type));
    printf("  %-35s%s\n", "Machine:", ehdr_get_machine(ehdr->e_machine));
    printf("  %-35s%s%d\n", "Version:", "0x", ehdr->e_version);
    printf("  %-35s%s%lx\n", "Entry point address:", "0x", ehdr->e_entry);
    printf("  %-35s%ld %s\n", "Start of program headers:", ehdr->e_phoff, "(bytes into file)");
    printf("  %-35s%ld %s\n", "Start of section headers:", ehdr->e_shoff, "(bytes into file)");
    printf("  %-35s%s%x\n", "Flags:", "0x", ehdr->e_flags);
    printf("  %-35s%d %s\n", "Size of this header:", ehdr->e_ehsize, "(bytes)");
    printf("  %-35s%d %s\n", "Size of program headers:", ehdr->e_phentsize, "(bytes)");
    printf("  %-35s%d\n", "Number of program headers:", ehdr->e_phnum);
    printf("  %-35s%d %s\n","Size of section headers:", ehdr->e_shentsize, "(bytes)");
    printf("  %-35s%d\n", "Number of section headers:", ehdr->e_shnum);
    printf("  %-35s%d\n", "Section header string table index:", ehdr->e_shstrndx);
}



void swap(unsigned char *a, unsigned char *b)
{
   unsigned char t;

   t  = *b;
   *b = *a;
   *a = t;
}

/* Display the program header */
static void  dump_program_header(Elf64_Ehdr *ehdr, Elf64_Phdr *phdr, Elf64_Shdr *shdr)
{
    
    printf("\nElf file type is %s\n", ehdr_get_type(ehdr->e_type));
    printf("Entry point 0x%lx\n", ehdr->e_entry);
    printf("There are %d program headers, starting at offset %ld\n", 
            ehdr->e_phnum, phdr->p_offset);
    printf("\nProgram Headers:\n");
    printf("  %-15s%-19s%-19s%-19s\n", "Type", "Offset", "VirtAddr", "PhysAddr");
    printf("%*c%-19s%-19s%s\n", 17, ' ', "FileSiz", "MemSiz", "Flags Align");
    
    unsigned int i; 
    uint64_t map[3];
    unsigned char  buffer[100000] ;
    for (i = 0; i < ehdr->e_phnum; i++)
    {
        if(phdr[i].p_type==PT_LOAD)
        {
            /*changed to map shared, however, map shared can't be used with prot_write, 
            access writes need to be modified according to each segment,remove map anonymous, 
            return map anonymous since we are going to read using fseek and fread instead 
            remove map fixed since start addresses of sections may not be perfectly aligned*/
            map[i] =(uint64_t) mmap((void *)(phdr[i].p_vaddr), 
            phdr[i].p_memsz + 0x1000,
            PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
            printf("---->%016lx<----%x\n", map[i], errno );
            rewind (hdl->file);
            fseek(hdl->file,phdr[i].p_offset, SEEK_SET);
            fread((void*)phdr[i].p_vaddr, 1,phdr[i].p_filesz, hdl->file);
            printf("0x%16x\n", phdr[i].p_filesz);
            printf("  %-15s0x%016lx 0x%016lx 0x%016lx\n",phdr_get_type(phdr[i].p_type), 
                    phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr);  
            printf("%*c%s%016lx 0x%016lx  %-5s  %lx\n", 17, ' ',    "0x", 
                    phdr[i].p_filesz, phdr[i].p_memsz, phdr_get_flags(phdr[i].p_flags), 
                    phdr[i].p_align);

        }
    }
    return ;
}


/* Display the section header */
static void dump_section_header(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr )
{
    printf("There are %d section headers, starting at offset 0x%lx:\n\n", 
            ehdr->e_shnum, ehdr->e_shoff);
    printf("Section Headers:\n");
    printf("  %-23s%-17s%-18s%s\n", "[Nr] Name", "Type", "Address", "Offset");
    printf("       %-18s%-17s%s\n", "Size", "EntSize", "Flags  Link  Info  Align");
    
    char * stringTable= get_sectionHeader_string_table(ehdr);
    unsigned int i;
    for (i = 0; i < ehdr->e_shnum; i++)
    {
        const Elf64_Shdr *ite = &shdr[i];
        char * entry = stringTable + ite->sh_name;
        /*This gets the offset of the string we want, the string is 
        null-terminated so printf will detect the end of the string*/
        if(strcmp(entry, ".eh_frame")==0)
        {
            printf("[%*d] %-16s  %-16s %016lx  %08lx\n", 2, i,entry, 
                    shdr_get_type(ite->sh_type), ite->sh_addr, ite->sh_offset);
            printf("%016lx  %016lx  %-9s%-6d%-6d%ld\n",
                ite->sh_size, ite->sh_entsize, shdr_get_flags(ite->sh_flags), 
                ite->sh_link, ite->sh_info, ite->sh_addralign);
        }
    }
         printf("%s", key_to_flags);

}
 

static int  read_elf(struct argument *args)
{
    hdl = re_create_handle(args->file);
    if (hdl == NULL)
        return -1;

    /* retreive pointers for each elf file sections */
    Elf64_Ehdr *ehdr = re_get_elf_header(hdl);
    Elf64_Phdr *phdr = re_get_program_header(hdl);
    Elf64_Shdr *shdr = re_get_section_header(hdl);

    if (args->ehdr_flag)
        dump_elf_file_header(ehdr);

    if (args->phdr_flag)
         dump_program_header(ehdr, phdr, shdr);

    if (args->shdr_flag)
        dump_section_header(ehdr, shdr);

    re_free_handle(hdl);

    return 0;
}

int main(int argc, char **argv, char ** envp)
{
    struct argument args;
    argument_manager(argc, argv, &args);
    read_elf(&args);
    uint64_t ptr = (hdl->ehdr64->e_entry);
    uint64_t map =(uint64_t) mmap(NULL , \ 
                 1024*1024 /*1MB default size of the stack*/ , \
                   PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN, -1,0);
    printf("++++++++++++++++++++++>%16lx\n", map);    
    char file_name[]="./hello";
    printf("---->%016lx<----\n", ptr);
    printf("here\n");
    Elf64_Addr *elf_info;
    asm volatile("mov %%rsp, %0\n\t"
                :"=r"(elf_info)
                :
                :

    );
    for(int i =0;i<41;i++) elf_info--;
    NEW_AUX_ENT(AT_SYSINFO_EHDR, getauxval(AT_SYSINFO_EHDR));
    NEW_AUX_ENT(AT_HWCAP, getauxval(AT_HWCAP));
	NEW_AUX_ENT(AT_PAGESZ,0x1000);
	NEW_AUX_ENT(AT_CLKTCK, 100);
	NEW_AUX_ENT(AT_PHDR, 0x400000+hdl->ehdr64->e_phoff);
	NEW_AUX_ENT(AT_PHENT, 56);
	NEW_AUX_ENT(AT_PHNUM, hdl->ehdr64->e_phnum);
	NEW_AUX_ENT(AT_BASE, getauxval(AT_BASE));//address of the loader
	NEW_AUX_ENT(AT_FLAGS, getauxval(AT_FLAGS));
	NEW_AUX_ENT(AT_ENTRY, hdl->ehdr64->e_entry);
	NEW_AUX_ENT(AT_UID, 1000);
	NEW_AUX_ENT(AT_EUID,1000);
	NEW_AUX_ENT(AT_GID, 1000);
	NEW_AUX_ENT(AT_EGID, 1000);
	NEW_AUX_ENT(AT_SECURE, 0);
	NEW_AUX_ENT(AT_RANDOM, 0x401237);
	NEW_AUX_ENT(AT_HWCAP2, 0);
	NEW_AUX_ENT(AT_EXECFN ,argv[argc -1]);
	NEW_AUX_ENT(AT_PLATFORM,getauxval(AT_PLATFORM) );
    NEW_AUX_ENT(AT_BASE_PLATFORM,getauxval(AT_BASE_PLATFORM));
    elf_info+=1;
    elf_info-=41;
	
    asm volatile("mov %0, %%rsp\n\t"
                :
                :"r"(elf_info)
                :
    );
    char ** second_envp; 
    second_envp=envp;
    Elf64_auxv_t *auxv;
    //from stack diagram above: *envp = NULL marks end of envp
    while(*second_envp++ != NULL);
    asm volatile("pushq $0\n\t"
                    :
                    :
                    :);
    int envp_no=0;
    for( envp_no=0;envp[envp_no]!=NULL; envp_no++){}
    for(int i=envp_no-1;i>=0;i--)
    {
        asm volatile("pushq %0\n\t"
                            :
                            :"r"(envp[i])
                            :);
    }   
    asm volatile("pushq $0\n\t"
                    :
                    :
                    :);
    printf("%ld\n",envp_no);
    //argv excluding the final(the executable) and the switch(-l)
    for(int i=argc-1;i>=2;i--)
    {        
        printf("%s\n", argv[i]);
        asm volatile("pushq %0\n\t"
            :
            :"r"(argv[i])
            :);
    }
    asm volatile("pushq $1\n\t" //argc
                    :
                    :
                    :);
   asm volatile(
                "mov $0, %%rbx\n\t"
                "mov $0, %%rcx\n\t"               
                "mov $0, %%rdx\n\t"
                "mov $0, %%rdi\n\t"
                "mov %0,%%r10 \n\t"
                "jmp *%%r10 \n\t"
                :
                :"r"(ptr)
                :
                );
    printf("returned\n");
    return 0;
}