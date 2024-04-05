#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/smp.h>
#include <linux/sem.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/stat.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/utsname.h>
#include <linux/personality.h>
#include <linux/random.h>
#include <linux/uaccess.h>
#include <linux/elf.h>

#include <asm/ia32.h>
#include <asm/syscalls.h>

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mem_checkpoint.h>
#include <linux/hashtable.h>
#include <asm/io.h>

/*
 * Align a virtual address to avoid aliasing in the I$ on AMD F15h.
 */
static unsigned long get_align_mask(void)
{
	/* handle 32- and 64-bit case with a single conditional */
	if (va_align.flags < 0 || !(va_align.flags & (2 - mmap_is_ia32())))
		return 0;

	if (!(current->flags & PF_RANDOMIZE))
		return 0;

	return va_align.mask;
}

/*
 * To avoid aliasing in the I$ on AMD F15h, the bits defined by the
 * va_align.bits, [12:upper_bit), are set to a random value instead of
 * zeroing them. This random value is computed once per boot. This form
 * of ASLR is known as "per-boot ASLR".
 *
 * To achieve this, the random value is added to the info.align_offset
 * value before calling vm_unmapped_area() or ORed directly to the
 * address.
 */
static unsigned long get_align_bits(void)
{
	return va_align.bits & get_align_mask();
}

unsigned long align_vdso_addr(unsigned long addr)
{
	unsigned long align_mask = get_align_mask();
	addr = (addr + align_mask) & ~align_mask;
	return addr | get_align_bits();
}

static int __init control_va_addr_alignment(char *str)
{
	/* guard against enabling this on other CPU families */
	if (va_align.flags < 0)
		return 1;

	if (*str == 0)
		return 1;

	if (*str == '=')
		str++;

	if (!strcmp(str, "32"))
		va_align.flags = ALIGN_VA_32;
	else if (!strcmp(str, "64"))
		va_align.flags = ALIGN_VA_64;
	else if (!strcmp(str, "off"))
		va_align.flags = 0;
	else if (!strcmp(str, "on"))
		va_align.flags = ALIGN_VA_32 | ALIGN_VA_64;
	else
		return 0;

	return 1;
}
__setup("align_va_addr", control_va_addr_alignment);

SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, unsigned long, off)
{
	long error;
	error = -EINVAL;
	if (off & ~PAGE_MASK)
		goto out;

	error = sys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
out:
	return error;
}

struct page_info_node
{
    struct page_info info;
    /* locate in which file */
    __u8 file_no; 
    struct hlist_node node;
};

struct work_params {
	struct work_struct work;
	unsigned long begin;
	unsigned long end;
};

static size_t file_index_size = sizeof(struct file_index);
static size_t page_info_node_size = sizeof(struct page_info_node);
static size_t page_info_size = sizeof(struct page_info);

#define MAX_PAGE_NUM 256
// hash table for page_info_node
static DEFINE_HASHTABLE(pages_table, 8);

static int merge_info(struct file *fp, __u8 file_no)
{
	loff_t pos = 0;
	struct file_index index;
	__u8 count = 0;
	
	pr_info("merge_info enter\n");
	pr_info("merge_info fp = %p file_no = %u\n", fp, file_no);

	kernel_read(fp, &index, file_index_size, &pos);
	pos += file_index_size;
	pr_info("merge_info index.num = %u\n", index.num);
	for (count = 0; count < index.num; count++) {
		__u8 page_exist = 0;
		struct page_info_node *ite = NULL;
		struct page_info info;

		kernel_read(fp, &info, file_index_size, &pos);
		pos += page_info_size;

		hash_for_each_possible(pages_table, ite, node, info.index)
			page_exist = 1;
		pr_info("merge_info ite = %p page_exist = %u info.index = %lu info.offset = %u\n",
		ite, page_exist, info.index, info.offset);
		if (ite && page_exist) {
			ite->file_no = file_no;
			ite->info = info;
		} else {
			struct page_info_node *new_node = kmalloc(page_info_node_size, GFP_KERNEL);
			if (!new_node)
				return -ENOMEM;
			new_node->file_no = file_no;
			new_node->info = info;
			hash_add(pages_table, &new_node->node, info.index);
		}
	}
	
	pr_info("merge_info finish");
	return 0;
}

static void release_table(void)
{
	struct page_info_node *ite = NULL;
	int i;

	hash_for_each(pages_table, i, ite, node) {
		hash_del(&ite->node);
		kfree(ite);
	}
}

//static void save_mem(struct work_struct *work)
static void save_mem(unsigned long start_addr, unsigned long end_addr)
{
	char *file_name = NULL;
	void *old_page;
	struct file **fps = NULL;
	struct file *inc_fp = NULL;
	__u8 file_no = 0;
	__u8 page_count = 0;
	__u8 count = 0;
	unsigned long addr = 0;
	phys_addr_t last_page = 0;
	loff_t pos = 0;
	phys_addr_t *addr_array = NULL;
	struct file_index index;

	pr_info("save_mem begin\n");
	pr_info("save_mem start_addr = %lu end_addr = %lu current->mm = %p\n", 
	start_addr, end_addr, current->mm);

	fps = kmalloc(MAX_FILE_NUM * sizeof(struct file), GFP_KERNEL);
	file_name = kmalloc(MAX_NAME_LEN * sizeof(char), GFP_KERNEL);
	addr_array = kmalloc(MAX_PAGE_NUM * sizeof(phys_addr_t), GFP_KERNEL);
	old_page = kmalloc(PAGE_SIZE, GFP_KERNEL);

	while (1) {
		memset(file_name, 0, MAX_NAME_LEN * sizeof(char));
		sprintf(file_name, "/home/inc_cp_P%u", file_no);
		fps[file_no] = filp_open(file_name, O_RDONLY, 0);
		if (IS_ERR(fps[file_no]))
			break;
		if (merge_info(fps[file_no], file_no)) {
			pr_err("save_mem merge info for %s error\n", file_name);
			goto out;			
		}
		file_no++;
	}

	inc_fp = filp_open(file_name, O_WRONLY|O_CREAT|O_APPEND, 0644);
	if (IS_ERR(inc_fp)) {
		pr_err("save_mem open %s error\n", file_name);
		goto out;
	}
	fps[file_no] = inc_fp;

	// get number of pages
	for (addr = start_addr; addr <= end_addr; addr++) {
		struct page *curr_page = NULL;
		__u8 page_exist = 0;
		phys_addr_t start_phys_addr = 0;

		if (get_user_pages(current, current->mm, addr,
				1, VM_READ, 0, &curr_page, NULL) < 1)
			goto out;

		start_phys_addr = page_to_phys(curr_page);
		pr_info("save_mem virt_addr = %lu page = %p start_phys_addr = %llu\n",
		addr, curr_page, start_phys_addr);
		if (last_page != start_phys_addr) {
			void *start_virt_addr = page_address(curr_page);
			struct file_index old_index;
			loff_t offset = 0;
			struct page_info_node *ite = NULL;

			hash_for_each_possible(pages_table, ite, node, start_phys_addr)
				page_exist = 1;

			pr_info("addr = %p start_virt_addr = %p start_phys_addr = %llu page_exist = %u ite = %p\n",
			curr_page, start_virt_addr, start_phys_addr, page_exist, ite);

			if (ite && page_exist) {
				kernel_read(fps[ite->file_no], &old_index, file_index_size, &offset);
				offset = file_index_size + old_index.num * page_info_size + ite->info.offset * PAGE_SIZE;
				kernel_read(fps[ite->file_no], old_page, PAGE_SIZE, &offset);

				// compare with old files
				if (!memcmp(old_page, start_virt_addr, PAGE_SIZE))
					continue; // content in this page are identical
			}
			
			// record only, write to file later
			addr_array[page_count] = start_phys_addr;
			page_count++;
			last_page = start_phys_addr;
		} else
			put_page(curr_page);
	}

	// write file_index to file
	index.num = page_count;
	kernel_write(inc_fp, &index, page_info_size, &pos);
	pos += file_index_size;

	// write all page_info to file
	for (count = 0; count < page_count; count++) {
		struct page_info info = {
			.index = addr_array[count],
			.offset = count
		};
		kernel_write(inc_fp, &info, page_info_size, &pos);
		pos += page_info_size;
	}

	// write content in page to file and then release occupation
	for (count = 0; count < page_count; count++) {
		void *start_virt_addr = phys_to_virt(addr_array[count]);
		kernel_write(inc_fp, start_virt_addr, PAGE_SIZE, &pos);
		put_page(virt_to_page(start_virt_addr));
		pos += PAGE_SIZE;
	}


out:
	for (count = 0; count <= file_no; count++) {
		if (!IS_ERR(fps[count]))
			filp_close(fps[count], NULL);
	}

	if (old_page)
		kfree(old_page);
	if (addr_array)
		kfree(addr_array);
	if (fps)
		kfree(fps);
	if (file_name)
		kfree(file_name);
	release_table();

	pr_info("save_mem end");
}

//static struct workqueue_struct *my_wq;

SYSCALL_DEFINE2(cp_range, unsigned long, start_addr, unsigned long, end_addr)
{
	pr_info("cp_range begin");

	save_mem(start_addr, end_addr);

	pr_info("cp_range end");

	return 0;
}

static void find_start_end(unsigned long flags, unsigned long *begin,
			   unsigned long *end)
{
	if (!test_thread_flag(TIF_ADDR32) && (flags & MAP_32BIT)) {
		unsigned long new_begin;
		/* This is usually used needed to map code in small
		   model, so it needs to be in the first 31bit. Limit
		   it to that.  This means we need to move the
		   unmapped base down for this case. This can give
		   conflicts with the heap, but we assume that glibc
		   malloc knows how to fall back to mmap. Give it 1GB
		   of playground for now. -AK */
		*begin = 0x40000000;
		*end = 0x80000000;
		if (current->flags & PF_RANDOMIZE) {
			new_begin = randomize_range(*begin, *begin + 0x02000000, 0);
			if (new_begin)
				*begin = new_begin;
		}
	} else {
		*begin = current->mm->mmap_legacy_base;
		*end = TASK_SIZE;
	}
}

unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct vm_unmapped_area_info info;
	unsigned long begin, end;

	if (flags & MAP_FIXED)
		return addr;

	find_start_end(flags, &begin, &end);

	if (len > end)
		return -ENOMEM;

	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		if (end - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}

	info.flags = 0;
	info.length = len;
	info.low_limit = begin;
	info.high_limit = end;
	info.align_mask = 0;
	info.align_offset = pgoff << PAGE_SHIFT;
	if (filp) {
		info.align_mask = get_align_mask();
		info.align_offset += get_align_bits();
	}
	return vm_unmapped_area(&info);
}

unsigned long
arch_get_unmapped_area_topdown(struct file *filp, const unsigned long addr0,
			  const unsigned long len, const unsigned long pgoff,
			  const unsigned long flags)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long addr = addr0;
	struct vm_unmapped_area_info info;

	/* requested length too big for entire address space */
	if (len > TASK_SIZE)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

	/* for MAP_32BIT mappings we force the legacy mmap base */
	if (!test_thread_flag(TIF_ADDR32) && (flags & MAP_32BIT))
		goto bottomup;

	/* requesting a specific address */
	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		if (TASK_SIZE - len >= addr &&
				(!vma || addr + len <= vma->vm_start))
			return addr;
	}

	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	info.length = len;
	info.low_limit = PAGE_SIZE;
	info.high_limit = mm->mmap_base;
	info.align_mask = 0;
	info.align_offset = pgoff << PAGE_SHIFT;
	if (filp) {
		info.align_mask = get_align_mask();
		info.align_offset += get_align_bits();
	}
	addr = vm_unmapped_area(&info);
	if (!(addr & ~PAGE_MASK))
		return addr;
	VM_BUG_ON(addr != -ENOMEM);

bottomup:
	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	return arch_get_unmapped_area(filp, addr0, len, pgoff, flags);
}
