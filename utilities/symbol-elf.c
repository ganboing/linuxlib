#include <gelf.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include <btrfs/kerncompat.h>
#include <btrfs/list.h>

#include "kallsyms.h"
#include "map.h"
#include "symbol.h"
#include "util.h"

static int elf_read_maps(Elf *elf, bool exe, mapfn_t mapfn, void *data)
{
	GElf_Phdr phdr;
	size_t i, phdrnum;
	int err;
	u64 sz;

	if (elf_getphdrnum(elf, &phdrnum))
		return -1;

	for (i = 0; i < phdrnum; i++) {
		if (gelf_getphdr(elf, i, &phdr) == NULL)
			return -1;
		if (phdr.p_type != PT_LOAD)
			continue;
		if (exe) {
			if (!(phdr.p_flags & PF_X))
				continue;
		} else {
			if (!(phdr.p_flags & PF_R))
				continue;
		}
		sz = min(phdr.p_memsz, phdr.p_filesz);
		if (!sz)
			continue;
		err = mapfn(phdr.p_vaddr, sz, phdr.p_offset, data);
		if (err)
			return err;
	}
	return 0;
}

static int copy_bytes(int from, off_t from_offs, int to, off_t to_offs, u64 len)
{
	ssize_t r;
	size_t n;
	int err = -1;
	char *buf = malloc(page_size);

	if (buf == NULL)
		return -1;

	if (lseek(to, to_offs, SEEK_SET) != to_offs)
		goto out;

	if (lseek(from, from_offs, SEEK_SET) != from_offs)
		goto out;

	while (len) {
		n = page_size;
		if (len < n)
			n = len;
		/* Use read because mmap won't work on proc files */
		r = read(from, buf, n);
		if (r < 0)
			goto out;
		if (!r)
			break;
		n = r;
		r = write(to, buf, n);
		if (r < 0)
			goto out;
		if ((size_t)r != n)
			goto out;
		len -= n;
	}

	err = 0;
out:
	free(buf);
	return err;
}

struct kcore {
	int fd;
	int elfclass;
	Elf *elf;
	GElf_Ehdr ehdr;
};

static int kcore__open(struct kcore *kcore, const char *filename)
{
	GElf_Ehdr *ehdr;

	kcore->fd = open(filename, O_RDONLY);
	if (kcore->fd == -1)
		return -1;

	kcore->elf = elf_begin(kcore->fd, ELF_C_READ, NULL);
	if (!kcore->elf)
		goto out_close;

	kcore->elfclass = gelf_getclass(kcore->elf);
	if (kcore->elfclass == ELFCLASSNONE)
		goto out_end;

	ehdr = gelf_getehdr(kcore->elf, &kcore->ehdr);
	if (!ehdr)
		goto out_end;

	return 0;

out_end:
	elf_end(kcore->elf);
out_close:
	close(kcore->fd);
	return -1;
}

static int kcore__init(struct kcore *kcore, char *filename, int elfclass,
		       bool temp)
{
	kcore->elfclass = elfclass;

	if (temp) {
		FILE *f = tmpfile();
		kcore->fd = dup(fileno(f));
		fclose(f);
	} else
		kcore->fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0400);
	if (kcore->fd == -1)
		return -1;

	kcore->elf = elf_begin(kcore->fd, ELF_C_WRITE, NULL);
	if (!kcore->elf)
		goto out_close;

	if (!gelf_newehdr(kcore->elf, elfclass))
		goto out_end;

	memset(&kcore->ehdr, 0, sizeof(GElf_Ehdr));

	return 0;

out_end:
	elf_end(kcore->elf);
out_close:
	close(kcore->fd);
	if (filename) {
		unlink(filename);
	}
	return -1;
}

static void kcore__close(struct kcore *kcore)
{
	elf_end(kcore->elf);
	close(kcore->fd);
}

static int kcore__copy_hdr(struct kcore *from, struct kcore *to, size_t count)
{
	GElf_Ehdr *ehdr = &to->ehdr;
	GElf_Ehdr *kehdr = &from->ehdr;

	memcpy(ehdr->e_ident, kehdr->e_ident, EI_NIDENT);
	ehdr->e_type = kehdr->e_type;
	ehdr->e_machine = kehdr->e_machine;
	ehdr->e_version = kehdr->e_version;
	ehdr->e_entry = 0;
	ehdr->e_shoff = 0;
	ehdr->e_flags = kehdr->e_flags;
	ehdr->e_phnum = count;
	ehdr->e_shentsize = 0;
	ehdr->e_shnum = 0;
	ehdr->e_shstrndx = 0;

	if (from->elfclass == ELFCLASS32) {
		ehdr->e_phoff = sizeof(Elf32_Ehdr);
		ehdr->e_ehsize = sizeof(Elf32_Ehdr);
		ehdr->e_phentsize = sizeof(Elf32_Phdr);
	} else {
		ehdr->e_phoff = sizeof(Elf64_Ehdr);
		ehdr->e_ehsize = sizeof(Elf64_Ehdr);
		ehdr->e_phentsize = sizeof(Elf64_Phdr);
	}

	if (!gelf_update_ehdr(to->elf, ehdr))
		return -1;

	if (!gelf_newphdr(to->elf, count))
		return -1;

	return 0;
}

static int kcore__add_phdr(struct kcore *kcore, int idx, off_t offset, u64 addr,
			   u64 len)
{
	GElf_Phdr phdr = {
		.p_type = PT_LOAD,
		.p_flags = PF_R | PF_W | PF_X,
		.p_offset = offset,
		.p_vaddr = addr,
		.p_paddr = 0,
		.p_filesz = len,
		.p_memsz = len,
		.p_align = page_size,
	};

	if (!gelf_update_phdr(kcore->elf, idx, &phdr))
		return -1;

	return 0;
}

static off_t kcore__write(struct kcore *kcore)
{
	return elf_update(kcore->elf, ELF_C_WRITE);
}

struct phdr_data {
	off_t offset;
	off_t rel;
	u64 addr;
	u64 len;
	struct list_head node;
	struct phdr_data *remaps;
};

struct sym_data {
	u64 addr;
	struct list_head node;
};

struct kcore_copy_info {
	u64 stext;
	u64 etext;
	u64 first_symbol;
	u64 last_symbol;
	u64 first_module;
	u64 last_module_symbol;
	size_t phnum;
	struct list_head phdrs;
	struct list_head syms;
};

#define kcore_copy__for_each_phdr(k, p)                                        \
	list_for_each_entry ((p), &(k)->phdrs, node)

static struct phdr_data *phdr_data__new(u64 addr, u64 len, off_t offset)
{
	struct phdr_data *p = calloc(1, sizeof(*p));

	if (p) {
		p->addr = addr;
		p->len = len;
		p->offset = offset;
	}

	return p;
}

static struct phdr_data *kcore_copy_info__addnew(struct kcore_copy_info *kci,
						 u64 addr, u64 len,
						 off_t offset)
{
	struct phdr_data *p = phdr_data__new(addr, len, offset);

	if (p)
		list_add_tail(&p->node, &kci->phdrs);

	return p;
}

static void kcore_copy__free_phdrs(struct kcore_copy_info *kci)
{
	struct phdr_data *p, *tmp;

	list_for_each_entry_safe (p, tmp, &kci->phdrs, node) {
		list_del_init(&p->node);
		free(p);
	}
}

static struct sym_data *kcore_copy__new_sym(struct kcore_copy_info *kci,
					    u64 addr)
{
	struct sym_data *s = calloc(1, sizeof(*s));

	if (s) {
		s->addr = addr;
		list_add_tail(&s->node, &kci->syms);
	}

	return s;
}

static void kcore_copy__free_syms(struct kcore_copy_info *kci)
{
	struct sym_data *s, *tmp;

	list_for_each_entry_safe (s, tmp, &kci->syms, node) {
		list_del_init(&s->node);
		free(s);
	}
}

static int kcore_copy__process_kallsyms(void *arg, const char *name, char type,
					u64 start)
{
	struct kcore_copy_info *kci = arg;

	if (!kallsyms__is_function(type))
		goto not_function;

	if (strchr(name, '[')) {
		if (start > kci->last_module_symbol)
			kci->last_module_symbol = start;
		return 0;
	}

	if (!kci->first_symbol || start < kci->first_symbol)
		kci->first_symbol = start;

	if (!kci->last_symbol || start > kci->last_symbol)
		kci->last_symbol = start;
not_function:
	if (!strcmp(name, "_stext")) {
		kci->stext = start;
		return 0;
	}

	if (!strcmp(name, "__brk_limit")) {
		kci->etext = start;
		return 0;
	}

	if (is_entry_trampoline(name) && !kcore_copy__new_sym(kci, start))
		return -1;

	return 0;
}

static int kcore_copy__parse_kallsyms(struct kcore_copy_info *kci,
				      const char *dir)
{
	char kallsyms_filename[PATH_MAX];

	snprintf(kallsyms_filename, PATH_MAX, "%s/kallsyms", dir);

	if (symbol__restricted_filename(kallsyms_filename, "/proc/kallsyms"))
		return -1;

	if (kallsyms__parse(kallsyms_filename, kci,
			    kcore_copy__process_kallsyms) < 0)
		return -1;

	return 0;
}

static int kcore_copy__process_modules(void *arg,
				       const char *name,
				       u64 start, u64 size,
				       u64 lastaddr)
{
	struct kcore_copy_info *kci = arg;

	if (!kci->first_module || start < kci->first_module)
		kci->first_module = start;

	//fprintf(stderr, "lastaddr=%" PRIx64 "\n", lastaddr);

	if (lastaddr != 0 && kci->last_module_symbol < lastaddr)
		kci->last_module_symbol = lastaddr;

	return 0;
}

static int kcore_copy__parse_modules(struct kcore_copy_info *kci,
				     const char *proc_dir, const char *sys_dir)
{
	if (modules__parse(proc_dir, sys_dir, kci,
			   kcore_copy__process_modules) < 0)
		return -1;

	return 0;
}

static int kcore_copy__map(struct kcore_copy_info *kci, u64 start, u64 end,
			   u64 pgoff, u64 s, u64 e)
{
	u64 len, offset;

	if (s < start || s >= end)
		return 0;

	offset = (s - start) + pgoff;
	len = e < end ? e - s : end - s;

	return kcore_copy_info__addnew(kci, s, len, offset) ? 0 : -1;
}

static int kcore_copy__read_map(u64 start, u64 len, u64 pgoff, void *data)
{
	struct kcore_copy_info *kci = data;
	u64 end = start + len;
	struct sym_data *sdat;

	//fprintf(stderr, "kci->last_module_symbol=%" PRIx64 "\n",
	//	kci->last_module_symbol);

	if (kcore_copy__map(kci, start, end, pgoff, kci->stext, kci->etext))
		return -1;

	if (kcore_copy__map(kci, start, end, pgoff, kci->first_module,
			    kci->last_module_symbol))
		return -1;

	list_for_each_entry (sdat, &kci->syms, node) {
		u64 s = round_down(sdat->addr, page_size);

		if (kcore_copy__map(kci, start, end, pgoff, s, s + len))
			return -1;
	}

	return 0;
}

static int kcore_copy__read_maps(struct kcore_copy_info *kci, Elf *elf)
{
	if (elf_read_maps(elf, true, kcore_copy__read_map, kci) < 0)
		return -1;

	return 0;
}

static void kcore_copy__find_remaps(struct kcore_copy_info *kci)
{
	struct phdr_data *p, *k = NULL;
	u64 kend;

	if (!kci->stext)
		return;

	/* Find phdr that corresponds to the kernel map (contains stext) */
	kcore_copy__for_each_phdr(kci, p)
	{
		u64 pend = p->addr + p->len - 1;

		if (p->addr <= kci->stext && pend >= kci->stext) {
			k = p;
			break;
		}
	}

	if (!k)
		return;

	kend = k->offset + k->len;

	/* Find phdrs that remap the kernel */
	kcore_copy__for_each_phdr(kci, p)
	{
		u64 pend = p->offset + p->len;

		if (p == k)
			continue;

		if (p->offset >= k->offset && pend <= kend)
			p->remaps = k;
	}
}

static void kcore_copy__layout(struct kcore_copy_info *kci)
{
	struct phdr_data *p;
	off_t rel = 0;

	kcore_copy__find_remaps(kci);

	kcore_copy__for_each_phdr(kci, p)
	{
		if (!p->remaps) {
			p->rel = rel;
			rel += p->len;
		}
		kci->phnum += 1;
	}

	kcore_copy__for_each_phdr(kci, p)
	{
		struct phdr_data *k = p->remaps;

		if (k)
			p->rel = p->offset - k->offset + k->rel;
	}
}

static int kcore_copy__calc_maps(struct kcore_copy_info *kci,
				 const char *proc_dir, const char *sys_dir, Elf *elf)
{
	if (kcore_copy__parse_kallsyms(kci, proc_dir))
		return -1;

	if (kcore_copy__parse_modules(kci, proc_dir, sys_dir))
		return -1;

	if (kci->stext)
		kci->stext = round_down(kci->stext, page_size);
	else
		kci->stext = round_down(kci->first_symbol, page_size);

	if (kci->etext) {
		kci->etext = round_up(kci->etext, page_size);
	} else if (kci->last_symbol) {
		kci->etext = round_up(kci->last_symbol, page_size);
		kci->etext += page_size;
	}

	kci->first_module = round_down(kci->first_module, page_size);

	if (kci->last_module_symbol) {
		kci->last_module_symbol =
			round_up(kci->last_module_symbol, page_size);
		kci->last_module_symbol += page_size;
	}

	if (!kci->stext || !kci->etext)
		return -1;

	if (kci->first_module && !kci->last_module_symbol)
		return -1;

	if (kcore_copy__read_maps(kci, elf))
		return -1;

	kcore_copy__layout(kci);

	return 0;
}

int kcore_copy__copy_file(const char *from_dir, const char *to_dir,
			  const char *name)
{
	char from_filename[PATH_MAX];
	char to_filename[PATH_MAX];

	snprintf(from_filename, PATH_MAX, "%s/%s", from_dir, name);
	snprintf(to_filename, PATH_MAX, "%s/%s", to_dir, name);

	return copyfile_mode(from_filename, to_filename, 0600);
}

int kcore_copy__unlink(const char *dir, const char *name)
{
	char filename[PATH_MAX];

	snprintf(filename, PATH_MAX, "%s/%s", dir, name);

	return unlink(filename);
}

static int kcore_copy__compare_fds(int from, int to)
{
	char *buf_from;
	char *buf_to;
	ssize_t ret;
	size_t len;
	int err = -1;

	buf_from = malloc(page_size);
	buf_to = malloc(page_size);
	if (!buf_from || !buf_to)
		goto out;

	while (1) {
		/* Use read because mmap won't work on proc files */
		ret = read(from, buf_from, page_size);
		if (ret < 0)
			goto out;

		if (!ret)
			break;

		len = ret;

		if (readn(to, buf_to, len) != (int)len)
			goto out;

		if (memcmp(buf_from, buf_to, len))
			goto out;
	}

	err = 0;
out:
	free(buf_to);
	free(buf_from);
	return err;
}

static int kcore_copy__compare_files(const char *from_filename,
				     const char *to_filename)
{
	int from, to, err = -1;

	from = open(from_filename, O_RDONLY);
	if (from < 0)
		return -1;

	to = open(to_filename, O_RDONLY);
	if (to < 0)
		goto out_close_from;

	err = kcore_copy__compare_fds(from, to);

	close(to);
out_close_from:
	close(from);
	return err;
}

int kcore_copy__compare_file(const char *from_dir, const char *to_dir,
			     const char *name)
{
	char from_filename[PATH_MAX];
	char to_filename[PATH_MAX];

	snprintf(from_filename, PATH_MAX, "%s/%s", from_dir, name);
	snprintf(to_filename, PATH_MAX, "%s/%s", to_dir, name);

	return kcore_copy__compare_files(from_filename, to_filename);
}

/**
 * kcore_copy - copy kallsyms, modules and kcore from one directory to another.
 * @from_dir: from directory
 * @to_dir: to directory
 *
 * This function copies kallsyms, modules and kcore files from one directory to
 * another.  kallsyms and modules are copied entirely.  Only code segments are
 * copied from kcore.  It is assumed that two segments suffice: one for the
 * kernel proper and one for all the modules.  The code segments are determined
 * from kallsyms and modules files.  The kernel map starts at _stext or the
 * lowest function symbol, and ends at _etext or the highest function symbol.
 * The module map starts at the lowest module address and ends at the highest
 * module symbol.  Start addresses are rounded down to the nearest page.  End
 * addresses are rounded up to the nearest page.  An extra page is added to the
 * highest kernel symbol and highest module symbol to, hopefully, encompass that
 * symbol too.  Because it contains only code sections, the resulting kcore is
 * unusual.  One significant peculiarity is that the mapping (start -> pgoff)
 * is not the same for the kernel map and the modules map.  That happens because
 * the data is copied adjacently whereas the original kcore has gaps.  Finally,
 * kallsyms and modules files are compared with their copies to check that
 * modules have not been loaded or unloaded while the copies were taking place.
 *
 * Return: %0 on success, %-1 on failure.
 */
int kcore_copy(const char *from_dir, const char *sys_dir)
{
	struct kcore kcore;
	struct kcore extract;
	int idx = 0, ret = -1 /*, err = -1*/;
	off_t offset, sz;
	struct kcore_copy_info kci = {
		.stext = 0,
	};
	char kcore_filename[PATH_MAX];
	//char extract_filename[PATH_MAX];
	struct phdr_data *p;

	INIT_LIST_HEAD(&kci.phdrs);
	INIT_LIST_HEAD(&kci.syms);

	//if (kcore_copy__copy_file(from_dir, to_dir, "kallsyms"))
	//	return -1;

	//if (kcore_copy__copy_file(from_dir, to_dir, "modules"))
	//	goto out_unlink_kallsyms;

	snprintf(kcore_filename, PATH_MAX, "%s/kcore", from_dir);
	//scnprintf(extract_filename, PATH_MAX, "%s/kcore", to_dir);

	if (kcore__open(&kcore, kcore_filename))
		goto out_unlink_modules;

	if (kcore_copy__calc_maps(&kci, from_dir, sys_dir, kcore.elf))
		goto out_kcore_close;

	if (kcore__init(&extract, /*extract_filename*/ NULL, kcore.elfclass,
			true))
		goto out_kcore_close;

	if (kcore__copy_hdr(&kcore, &extract, kci.phnum))
		goto out_extract_close;

	offset = gelf_fsize(extract.elf, ELF_T_EHDR, 1, EV_CURRENT) +
		 gelf_fsize(extract.elf, ELF_T_PHDR, kci.phnum, EV_CURRENT);
	offset = round_up(offset, page_size);

	kcore_copy__for_each_phdr(&kci, p)
	{
		off_t offs = p->rel + offset;

		if (kcore__add_phdr(&extract, idx++, offs, p->addr, p->len))
			goto out_extract_close;
	}

	sz = kcore__write(&extract);
	if (sz < 0 || sz > offset)
		goto out_extract_close;

	kcore_copy__for_each_phdr(&kci, p)
	{
		off_t offs = p->rel + offset;

		if (p->remaps)
			continue;
		if (copy_bytes(kcore.fd, p->offset, extract.fd, offs, p->len))
			goto out_extract_close;
	}

	//if (kcore_copy__compare_file(from_dir, to_dir, "modules"))
	//	goto out_extract_close;

	//if (kcore_copy__compare_file(from_dir, to_dir, "kallsyms"))
	//	goto out_extract_close;

	//err = 0;
	ret = dup(extract.fd);

out_extract_close:
	kcore__close(&extract);
	//if (err)
	//	unlink(extract_filename);
out_kcore_close:
	kcore__close(&kcore);
out_unlink_modules:
	//if (err)
	//	kcore_copy__unlink(to_dir, "modules");
	//out_unlink_kallsyms:
	//if (err)
	//	kcore_copy__unlink(to_dir, "kallsyms");

	kcore_copy__free_phdrs(&kci);
	kcore_copy__free_syms(&kci);

	return ret;
}
