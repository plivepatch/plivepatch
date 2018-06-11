#include <stdio.h>
#include <string.h>
#include <elf.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <sys/user.h>
#include <link.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bits/dlfcn.h>

#if defined(__x86_64__)
#define ARCH "x86_64"
#define IMAGE_ADDR 0x00400000
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym  Elf_Sym;
typedef Elf64_Dyn Elf_Dyn;
typedef Elf64_Word Elf_Word;
typedef Elf64_Word Dyn_Val;
typedef Elf64_Addr Elf_Addr;
#define ELF_ST_TYPE(X) ELF64_ST_TYPE(X)
#define ELF_ST_BIND(X) ELF64_ST_BIND(X)
#define ELF_ST_VISIBILITY(X) ELF64_ST_VISIBILITY(X)
typedef Elf64_Rel  Elf_Rel;
typedef Elf64_Rela Elf_Rela;
#define ELF_R_SYM(X)  ELF32_R_SYM(X)
#define ELF_R_TYPE(X) ELF64_R_TYPE(X)
#else
#define ARCH "x86"
#define IMAGE_ADDR 0x08048000
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Sym  Elf_Sym;
typedef Elf32_Dyn Elf_Dyn;
typedef Elf32_Word Elf_Word;
typedef Elf32_Word Dyn_Val;
typedef Elf32_Addr Elf_Addr;
#define ELF_ST_TYPE(X) ELF32_ST_TYPE(X)
#define ELF_ST_BIND(X) ELF32_ST_BIND(X)
#define ELF_ST_VISIBILITY(X) ELF32_ST_VISIBILITY(X)
typedef Elf32_Rel  Elf_Rel;
typedef Elf32_Rela Elf_Rela;
#define ELF_R_SYM(X)  ELF32_R_SYM(X)
#define ELF_R_TYPE(X) ELF32_R_TYPE(X)
#endif // __x86_64__

#define STRLEN 1024
#define ElfW(type)      _ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)    _ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)   e##w##t

//公共变量
struct user_regs_struct oldregs;
Elf_Addr lmap_addr;
Elf_Addr phdr_addr;
Elf_Addr dyn_addr;

struct lmap_result {
    Elf_Addr symtab;
    Elf_Addr strtab;
    Elf_Addr jmprel;
    Elf_Addr reldyn;
    uint64_t link_addr;
    uint64_t nsymbols;
    uint64_t nrelplts;
    uint64_t nreldyns;
};

void die(const char *s)
{
    perror(s);
    exit(errno);
}

static void ptrace_readreg(pid_t pid, struct user_regs_struct *regs)
{
    if(ptrace(PTRACE_GETREGS, pid, NULL, regs)) {
        printf("*** ptrace_readreg error ***\n");
    }
}

static void ptrace_writereg(pid_t pid, struct user_regs_struct *regs)
{
    if(ptrace(PTRACE_SETREGS, pid, NULL, regs)) {
        printf("*** ptrace_writereg error ***\n");
    }
}

void ptrace_attach(pid_t pid)
{
    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace_attach");
        exit(-1);
    }
    
    waitpid(pid, NULL, WUNTRACED);
    
    ptrace_readreg(pid, &oldregs);
}

void ptrace_detach(pid_t pid)
{
    ptrace_writereg(pid, &oldregs);

    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        perror("ptrace_detach");
        exit(-1);
    }
}

/* 读指定进程 */
int ptrace_read(int pid, unsigned long addr, void *vptr, int len)
{
    int i,count;
    long word;
    unsigned long *ptr = (unsigned long *)vptr;
 
    i = count = 0;
    while (count < len) {
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + count, NULL);
        while(word < 0)
        {
            if(errno == 0)
                break;
            perror("ptrace_read failed");
            return 2;
        }
        count += sizeof(long);
        ptr[i++] = word;
    }
    return 0;
}

/* 写指定进程地址 */
void ptrace_write(int pid, unsigned long addr, void *vptr, int len)
{
    int count;
    long word;
 
    count = 0;
    while(count < len) {
        memcpy(&word, vptr + count, sizeof(word));
        word = ptrace(PTRACE_POKETEXT, pid, addr + count, word);
        count += 4;
 
        if(errno != 0)
            printf("ptrace_write failed\t %ld\n", addr + count);
    }
}
 
/*
 在进程指定地址读一个字符串
 */
unsigned int ptrace_readstr(int pid, unsigned long addr, char *buf, unsigned int len)
{
    char *str = (char *) malloc(64);
    int i,count;
    long word;
    char *pa;
 
    i = count = 0;
    pa = (char *)&word;
 
    while(i <= 60) {
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + count, NULL);
        count += 4;
 
        if (pa[0] == 0) {
            str[i] = 0;
        break;
        }
        else
            str[i++] = pa[0];
 
        if (pa[1] == 0) {
            str[i] = 0;
            break;
        }
        else
            str[i++] = pa[1];
 
        if (pa[2] ==0) {
            str[i] = 0;
            break;
        }
        else
            str[i++] = pa[2];
 
        if (pa[3] ==0) {
            str[i] = 0;
            break;
        }
        else
            str[i++] = pa[3];
    }
    
    if (i < len) {
	memset(buf,0,len);
    	strncpy(buf, str, i);
    }

    return i;
}

/* 取得指向link_map链表首项的指针 */
struct link_map * get_linkmap(int pid)
{
    int i;
    Elf_Ehdr *ehdr = (Elf_Ehdr *) malloc(sizeof(Elf_Ehdr)); 
    Elf_Phdr *phdr = (Elf_Phdr *) malloc(sizeof(Elf_Phdr));
    Elf_Dyn  *dyn = (Elf_Dyn *) malloc(sizeof(Elf_Dyn));
    Elf_Addr *gotplt;

    // 读取文件头
    ptrace_read(pid, IMAGE_ADDR, ehdr, sizeof(Elf_Ehdr));

    // 获取program headers table的地址
    phdr_addr = IMAGE_ADDR + ehdr->e_phoff;
    
    // 遍历program headers table，找到.dynamic
    for (i = 0; i < ehdr->e_phnum; i++) {
        ptrace_read(pid, phdr_addr + i * sizeof(Elf_Phdr), phdr, sizeof(Elf_Phdr));
        if (phdr->p_type == PT_DYNAMIC) {
            dyn_addr = phdr->p_vaddr;
            break;
        }
    }
    
    if (0 == dyn_addr) {
        printf(" >> cannot locate the address of .dynamin\n");
	    exit(0);
    } else {
        printf(" >> the address of .dynamic is %p\n", (void *)dyn_addr);
    }

    // 遍历.dynamic，找到.got.plt 
    for (i = 0; i * sizeof(Elf_Dyn) <= phdr->p_memsz; i++ ) {
        ptrace_read(pid, dyn_addr + i * sizeof(Elf_Dyn), dyn, sizeof(Elf_Dyn));
        if (dyn->d_tag == DT_PLTGOT) {
            gotplt = (Elf_Addr *)(dyn->d_un.d_ptr);
            break;
        }
    }
    if (NULL == gotplt) {
        printf(" >> cannot locate the address of .got.plt\n");
	    exit(0);
    } else {
        printf(" >> the address of .got.plt is %p\n", gotplt);
    }

    // 获取link_map地址
    ptrace_read(pid, (Elf_Addr)(gotplt + 1), &lmap_addr, sizeof(Elf_Addr));
    printf(" >> the address of link_map is %p\n", (void *)lmap_addr);

    free(ehdr);
    free(phdr);
    free(dyn);

    return (struct link_map *)lmap_addr;
}

/*
 * 取得给定link_map指向的SYMTAB、STRTAB、RELPLT、REPLDYN信息
 * 这些地址信息将被保存到全局变量中，以方便使用
 */
struct lmap_result *handle_one_lmap(int pid, struct link_map *lm)
{
    Elf_Addr dyn_addr;
    Elf_Dyn  *dyn = (Elf_Dyn *)calloc(1, sizeof(Elf_Dyn));
    struct lmap_result *lmret = NULL;

    // 符号表
    Elf_Addr    symtab;
    Dyn_Val     syment;
    Dyn_Val     symsz;
    // 字符串表
    Elf_Addr    strtab;
    // rel.plt
    Elf_Addr    jmprel;
    Dyn_Val     relpltsz;
    // rel.dyn
    Elf_Addr    reldyn;
    Dyn_Val     reldynsz;
    // size of one REL relocs or RELA relocs
    Dyn_Val     relent;
    // 每个lmap对应的库的映射基地址
    Elf_Addr    link_addr;

    link_addr = lm->l_addr;
    dyn_addr = lm->l_ld;

    ptrace_read(pid, dyn_addr, dyn, sizeof(Elf_Dyn));

    while(dyn->d_tag != DT_NULL){
        switch(dyn->d_tag)
        {
        // 符号表
        case DT_SYMTAB:
            symtab = dyn->d_un.d_ptr;
            break;
        case DT_SYMENT:
            syment = dyn->d_un.d_val;
            break;
        case DT_SYMINSZ:
            symsz = dyn->d_un.d_val;
            break;
        // 字符串表
        case DT_STRTAB:
            strtab = dyn->d_un.d_ptr;
            break;
        // rel.plt, Address of PLT relocs
        case DT_JMPREL:
            jmprel = dyn->d_un.d_ptr;
            break;
        // rel.plt, Size in bytes of PLT relocs
        case DT_PLTRELSZ:
            relpltsz = dyn->d_un.d_val;
            break;
        // rel.dyn, Address of Rel relocs
        case DT_REL:
        case DT_RELA:
            reldyn = dyn->d_un.d_ptr;
            break;
        // rel.dyn, Size of one Rel reloc
        case DT_RELENT:
        case DT_RELAENT:
            relent = dyn->d_un.d_val;
            break;
        //rel.dyn  Total size of Rel relocs
        case DT_RELSZ:
        case DT_RELASZ:
            reldynsz = dyn->d_un.d_val;
            break;
        }
        ptrace_read(pid, dyn_addr += (sizeof(Elf_Dyn)/sizeof(Elf_Addr)), dyn, sizeof(Elf_Dyn));
    }
    if (0 == syment || 0 == relent) {
        printf("Invalid ent, syment=%u, relent=%u\n", (unsigned)syment, (unsigned)relent);
        return lmret;
    }

    lmret = (struct lmap_result *)calloc(1, sizeof(struct lmap_result));
    lmret->symtab = symtab;
    lmret->strtab = strtab;
    lmret->jmprel = jmprel;
    lmret->reldyn = reldyn;
    lmret->link_addr = link_addr;
    lmret->nsymbols = symsz / syment;
    lmret->nrelplts = relpltsz / relent;
    lmret->nreldyns = reldynsz / relent;
    
    free(dyn);

    return lmret;
}

Elf_Addr find_symbol_in_linkmap(int pid, struct link_map *lm, char *sym_name)
{
    int i = 0;
    char buf[STRLEN] = {0};
    unsigned int nlen = 0;
    Elf_Addr ret;
    Elf_Sym *sym = (Elf_Sym *)malloc(sizeof(Elf_Sym)); 

    struct lmap_result *lmret = handle_one_lmap(pid, lm);

    for(i = 0; i >= 0; i++) {
        // 读取link_map的符号表
        ptrace_read(pid, lmret->symtab + i * sizeof(Elf_Sym), sym, sizeof(Elf_Sym));

        // 全为0，是符号表的第一项
        if (!sym->st_name && !sym->st_size && !sym->st_value) {
            continue;
        }
        nlen = ptrace_readstr(pid, lmret->strtab + sym->st_name, buf, 128);
        if (buf[0] && (32 > buf[0] || 127 == buf[0])) {
            printf(" >> !!!find symbol is over!!!\n");
            return 0;
        }

        printf("find symbol name: %s\n",buf);
        if (strcmp(buf, sym_name) == 0) {
            if(sym->st_value == 0) {
                // 值为0，代表这个符号本身就是重定向的内容
                continue;
            }else {
                // 否则说明找到了符号
                return (lmret->link_addr + sym->st_value);
            }
        }

    }

    free(sym);
    return 0;
}

/*符号查找，该函数主要实现link_map遍历 */
Elf_Addr find_symbol(int pid, Elf_Addr lm_addr, char *sym_name)
{
    char buf[STRLEN] = {0};
    struct link_map lmap;
    unsigned int nlen = 0;

    while (lm_addr) {
        // 读取link_map结构内容
        ptrace_read(pid, lm_addr, &lmap, sizeof(struct link_map));
        lm_addr = (Elf_Addr)(lmap.l_next);

        // 判断l_name是否有效
        if (0 == lmap.l_name) {
            printf(" >> invalid address of l_name\n");
            continue;
        }
        nlen = ptrace_readstr(pid, (Elf_Addr)lmap.l_name, buf, 128);
        if (0 == nlen || 0 == strlen(buf)) {
            printf(" >> invalud name of link_map at %p\n", (void *)lmap.l_name);
          continue;
        }
        printf(" >> scan symbol in %s:\n", buf);

        Elf_Addr sym_addr = find_symbol_in_linkmap(pid, &lmap, sym_name);
        if (sym_addr) {
            return sym_addr;
        }
    }

    return 0;
}

/*
在进程自身的映象中（即不包括动态共享库，无须遍历link_map链表）获得各种动态信息
*/
struct lmap_result *get_dyn_info(int pid)
{
    int i = 0;
    Dyn_Val relpltsz;
    Dyn_Val relent;
    Elf_Dyn *dyn = (Elf_Dyn *) malloc(sizeof(Elf_Dyn));
    struct lmap_result *lmret = NULL;
    lmret = (struct lmap_result *)calloc(1, sizeof(struct lmap_result));

    ptrace_read(pid, dyn_addr + i * sizeof(Elf_Dyn), dyn, sizeof(Elf_Dyn));
    i++;

    while(dyn->d_tag){
        switch(dyn->d_tag)
        {
        case DT_SYMTAB:
            //puts("DT_SYMTAB");
            lmret->symtab = dyn->d_un.d_ptr;
            break;
        case DT_STRTAB:
            //puts("DT_STRTAB");
            lmret->strtab = dyn->d_un.d_ptr;
            break;
        case DT_JMPREL:
            //puts("DT_JMPREL");
            lmret->jmprel = dyn->d_un.d_ptr;
            break;
        case DT_PLTRELSZ:
            //puts("DT_PLTRELSZ");
            relpltsz = dyn->d_un.d_val;
            break;
        case DT_RELENT:
        case DT_RELAENT:
            //puts("DT_RELENT");
            relent = dyn->d_un.d_val;
            break;
        }
        ptrace_read(pid, dyn_addr + i * sizeof(Elf_Dyn), dyn, sizeof(Elf_Dyn));
        i++;
    }
    lmret->nrelplts = relpltsz / relent;
    free(dyn);

    return lmret;
}

// 查找符号的重定位地址 
Elf_Addr find_sym_in_rel(int pid, char *sym_name)
{
    Elf_Rel *rel = (Elf_Rel *) malloc(sizeof(Elf_Rel));
    Elf_Sym *sym = (Elf_Sym *) malloc(sizeof(Elf_Sym));
    int i;
    char str[STRLEN] = {0};
    unsigned long ret;
    struct lmap_result *lmret = get_dyn_info(pid);

    for (i = 0; i<lmret->nrelplts; i++) {
        ptrace_read(pid, lmret->jmprel + i*sizeof(Elf_Rela), rel, sizeof(Elf_Rela));
        ptrace_read(pid, lmret->symtab + ELF64_R_SYM(rel->r_info) * sizeof(Elf_Sym), sym, sizeof(Elf_Sym));
        int n = ptrace_readstr(pid, lmret->strtab + sym->st_name, str, STRLEN);
        printf("self->st_name: %s, self->r_offset = %p\n",str, rel->r_offset);
        if (strcmp(str, sym_name) == 0) {
            break;
        }
    }
    if (i == lmret->nrelplts)
        ret = 0;
    else
        ret = rel->r_offset;
    free(rel);
    return ret;
}

/*
#define RTLD_LAZY           0x00001
#define RTLD_NOW            0x00002
#define RTLD_BINDING_MASK   0x3
#define RTLD_NOLOAD         0x00004
#define RTLD_DEEPBIND       0x00008
#define RTLD_GLOBAL         0x00100
#define RTLD_LOCAL          0
#define RTLD_NODELETE       0x01000
*/

char *find_libc_start(pid_t pid)
{
    char path[STRLEN];
    char buf[STRLEN], *start = NULL, *end = NULL, *p = NULL;
    char *addr1 = NULL, *addr2 = NULL;
    FILE *f = NULL;
    

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    if ((f = fopen(path, "r")) == NULL)
        die("fopen");

    for (;;) {
        if (!fgets(buf, sizeof(buf), f))
            break;
        if (!strstr(buf, "r-xp"))
            continue;
        if (!(p = strstr(buf, "/")))
            continue;
        if (!strstr(p, "/libc-"))
            continue;
        start = strtok(buf, "-");
        addr1 = (char *)strtoul(start, NULL, 16);
        end = strtok(NULL, " ");
        addr2 = (char *)strtoul(end, NULL, 16);
        break;
    }

    fclose(f);    
    return addr1;
}

int inject_code(pid_t pid, unsigned long libc_addr, unsigned long dlopen_addr, char *dso)
{
    char sbuf1[STRLEN], sbuf2[STRLEN];
    struct user_regs_struct regs, saved_regs;
    int status;

    ptrace_readreg(pid, &regs);

    ptrace_read(pid, regs.rsp + STRLEN, sbuf1, sizeof(sbuf1));
    ptrace_read(pid, regs.rsp, sbuf2, sizeof(sbuf2));

    /* fake saved return address */
    libc_addr = 0x0;
    ptrace_write(pid, regs.rsp, (char *)&libc_addr, sizeof(libc_addr));
    ptrace_write(pid, regs.rsp + STRLEN, dso, strlen(dso) + 1); 

    memcpy(&saved_regs, &regs, sizeof(regs));

    /* pointer to &args */
    printf("rdi=%zx rsp=%zx rip=%zx\n", regs.rdi, regs.rsp, regs.rip);

    regs.rdi = regs.rsp + STRLEN;
    regs.rsi = RTLD_NOW|RTLD_GLOBAL|RTLD_NODELETE;
    regs.rip = dlopen_addr + 2;// kernel bug?! always need to add 2!

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
        die("ptrace 3");
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0)
        die("ptrace 4");

    /* Should receive a SIGSEGV */
    waitpid(pid, &status, 0);
    
    if (ptrace(PTRACE_SETREGS, pid, 0, &saved_regs) < 0)
        die("ptrace 5");

    ptrace_write(pid, saved_regs.rsp + 1024, sbuf1, sizeof(sbuf1));
    ptrace_write(pid, saved_regs.rsp, sbuf2, sizeof(sbuf2));

    return 0;
}

//程序开始
int main(int argc, char *argv[])
{
    int pid;
    int status = 0;
    struct link_map *map;
    char sym_name[STRLEN];
    char libpath[STRLEN];
    char oldfunname[STRLEN];
    char newfunname[STRLEN];
    Elf_Addr sym_addr;
    Elf_Addr new_sym_addr,old_sym_addr,rel_addr,target_addr;

    if(argc < 5){
        printf("example: ./plivepath pid patchlibpath oldfunname newfunname\n");
        exit(-1);
    }
    /* 从命令行取得目标进程PID*/
    pid = atoi(argv[1]);

    /* 从命令行取得新库名称*/
    memset(libpath,0,sizeof(libpath));
    memcpy(libpath,argv[2],strlen(argv[2]));
     
    /* 从命令行取得旧函数的名称*/
    memset(oldfunname,0,sizeof(oldfunname));
    memcpy(oldfunname,argv[3],strlen(argv[3]));
     
    /* 从命令行取得新函数的名称*/
    memset(newfunname,0,sizeof(newfunname));
    memcpy(newfunname,argv[4],strlen(argv[4]));
 
    printf("target pid = %d\n",pid);
    printf("target oldfunname: %s\n",oldfunname);
    printf("patch libpath: %s\n",libpath);
    printf("patch newfunname: %s\n",newfunname);

    /* 关联到目标进程*/
    ptrace_attach(pid);
    
    /* 得到指向link_map链表的指针 */
    map = get_linkmap(pid);
    
    /* 查找要被替换的函数 */
    sym_addr = find_symbol(pid, map, oldfunname);      
    printf("found %s at addr %p\n", sym_name, sym_addr);
    if(sym_addr == 0)
        goto detach;
    old_sym_addr = sym_addr;

    /* 发现__libc_dlopen_mode，并调用它加载patch.so动态链接库 */
    sym_addr = find_symbol(pid, map, "__libc_dlopen_mode");
    printf("found __libc_dlopen_mode at addr %p\n", sym_addr); 
    if(sym_addr == 0)
        goto detach;

    char *daemon_libc = NULL;
    daemon_libc = find_libc_start(pid);
    printf("daemon_libc: %p.\n",daemon_libc);
    inject_code(pid, daemon_libc, sym_addr, libpath);

    /* 找到新函数的地址 */
    strcpy(sym_name, newfunname);
    sym_addr = find_symbol(pid, map, sym_name);
    printf("===> found %s at addr %p\n", sym_name, sym_addr);
    if(sym_addr == 0)
        goto detach;
    new_sym_addr = sym_addr;

    /* 找到旧函数在重定向表的地址 */
    strcpy(sym_name, oldfunname);              
    printf("oldfunname: %s\n",sym_name);
    rel_addr = find_sym_in_rel(pid, sym_name);
    printf("%s rel addr\t %p\n", sym_name, rel_addr);
    
    if(rel_addr == 0)
        goto detach;
    
    ptrace_read(pid, rel_addr, &target_addr, sizeof(Elf_Addr));
    ptrace_write(pid, rel_addr, &new_sym_addr, sizeof(Elf_Addr));
    printf("===>oldfunction:%p -> newfunction:%p.\n",target_addr, new_sym_addr);

    puts("patch ok.");

    sleep(3);

    ptrace_detach(pid);

    exit(0);

detach:
    printf("prepare to detach\n");
    ptrace_detach(pid);
     
    return 0;
}
