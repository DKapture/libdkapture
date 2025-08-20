/**
 * sometimes we may accidentally delete a system file or else, there is no way
 * to retreat it back by traditional methods(except data recovery which is very
 * expensive).
 *
 * This module provides a way to retreat the file back, if it's still referenced
 * by any process. Mostly if the file deleted is of system file, it's much
 * likely being referenced by some other processes, so we can find the file from
 * the process and copy it back to the original path.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/miscdevice.h>
#include <linux/version.h>

#define FILE_DELETED " (deleted)"
#define FILE_DELETED_LEN (sizeof(FILE_DELETED) - 1)

static rwlock_t *ptasklist_lock;
static struct miscdevice misc;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 93) &&                          \
	LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 6)
static struct file
	*(*pf_uld_check_file)(struct fdtable *fdt, struct file *file, unsigned fd);
struct file *
uld_fcheck_file(struct fdtable *fdt, struct file *file, unsigned fd)
{
	return pf_uld_check_file(fdt, file, fd);
}
#endif

static int do_nothing(struct kprobe *p, struct pt_regs *regs)
{
	(void)p;
	(void)regs;
	return 0;
}

static typeof(kallsyms_lookup_name) *lookup_symbol;

static void *lookup_function(const char *func)
{
	int ret = -1;
	struct kprobe kp = {.symbol_name = func, .pre_handler = do_nothing};
	ret = register_kprobe(&kp);
	if (ret < 0)
	{
		pr_err("register_kprobe failed, error:%d\n", ret);
		return NULL;
	}

	unregister_kprobe(&kp);
	return kp.addr;
}

static int kfile_copy(struct file *from, struct file *to)
{
	int ret = 0;
	loff_t roff = 0;
	loff_t woff = 0;
	ssize_t rsz;
	ssize_t wsz;
	char *kbuf = NULL;

	kbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!kbuf)
	{
		return -ENOMEM;
	}

	while ((rsz = kernel_read(from, kbuf, PATH_MAX, &roff)) > 0)
	{
		wsz = kernel_write(to, kbuf, rsz, &woff);
		if (wsz != rsz)
		{
			pr_err("write failure: %ld", wsz);
			ret = -EFAULT;
			break;
		}
		pr_debug("%ld copied\n", wsz);
	}

	kfree(kbuf);
	return ret;
}

static struct file *find_task_path(struct task_struct *task, const char *path)
{
	/* Must be called with rcu_read_lock held */
	struct files_struct *files;
	unsigned int fd = 0;
	struct file *out_file = NULL;

	char *buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
	{
		pr_err("kmalloc failed\n");
		return NULL;
	}

	rcu_read_lock();
	task_lock(task);
	files = task->files;
	if (files)
	{
		for (; fd < files_fdtable(files)->max_fds; fd++)
		{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 6)
			struct file *file = files_lookup_fd_raw(files, fd);
#else
			struct file *file = files_lookup_fd_rcu(files, fd);
#endif
			if (!file)
			{
				continue;
			}

			char *ppath = file_path(file, buf, PATH_MAX);
			if (IS_ERR(ppath))
			{
				pr_err("file_path failed\n");
				continue;
			}
			size_t del = strlen(ppath);
			if (del > FILE_DELETED_LEN)
			{
				del -= FILE_DELETED_LEN;
				pr_debug("ppath del: %lu\n", del);
				if (strcmp(ppath + del, FILE_DELETED) == 0)
				{
					ppath[del] = '\0';
				}
			}
			pr_debug("ppath: %s vs path: %s\n", ppath, path);
			if (strncmp(path, ppath, PATH_MAX) == 0)
			{
				pr_debug("path match\n");
				out_file = get_file(file);
			}
		}
	}
	task_unlock(task);
	rcu_read_unlock();
	kfree(buf);
	return out_file;
}

static int retreat_path(const char *path)
{
	int ret;
	struct file *file = NULL;
	struct file *out_file = NULL;
	struct task_struct *p;

	if (path[0] != '/')
	{
		pr_err("path should be absolute\n");
		return -EINVAL;
	}

	read_lock(ptasklist_lock);
	for_each_process(p)
	{
		file = find_task_path(p, path);
		if (file)
		{
			break;
		}
	}
	read_unlock(ptasklist_lock);

	if (!file)
	{
		pr_debug("no file found\n");
		return -ENOENT;
	}

	out_file = filp_open(path, O_CREAT | O_WRONLY, 0744);
	if (!out_file)
	{
		ret = -EFAULT;
		pr_err("filp_open failed\n");
		goto exit;
	}

	ret = kfile_copy(file, out_file);
	if (ret)
	{
		pr_err("kfile_copy failed ret: %d\n", ret);
		goto exit;
	}

exit:
	if (out_file)
	{
		filp_close(out_file, NULL);
	}
	fput(file);
	return ret;
}

static ssize_t
misc_write(struct file *fp, const char *__user buf, size_t bsz, loff_t *off)
{
	if (bsz < 1)
	{
		return -EINVAL;
	}

	long ret;
	char *kbuf = NULL;

	if (bsz > PATH_MAX)
	{
		pr_err("buf no larger than 4096 once\n");
		return -E2BIG;
	}

	kbuf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!kbuf)
	{
		return -ENOMEM;
	}

	ret = copy_from_user(kbuf, buf, bsz);
	if (ret)
	{
		pr_err("copy failure\n");
		ret = -EFAULT;
		goto exit;
	}

	ret = retreat_path(kbuf);
	if (ret)
	{
		goto exit;
	}

exit:
	if (kbuf)
	{
		kfree(kbuf);
	}
	return ret;
}

static struct file_operations misc_fops = {
	.owner = THIS_MODULE,
	.write = misc_write
};

static int __init register_misc_dev(void)
{
	misc.minor = MISC_DYNAMIC_MINOR;
	misc.name = "retreat-file";
	misc.fops = &misc_fops;
	misc.mode = 0600;
	if (0 != misc_register(&misc))
	{
		return -1;
	}
	return 0;
}

static int __init retreat_init(void)
{
	lookup_symbol = lookup_function("kallsyms_lookup_name");
	if (!lookup_symbol)
	{
		pr_err("fail to lookup symbol 'kallsyms_lookup_name'\n");
		return -EFAULT;
	}

	ptasklist_lock = (typeof(ptasklist_lock))lookup_symbol("tasklist_lock");
	if (!ptasklist_lock)
	{
		pr_err("fail to lookup symbol 'tasklist_lock'\n");
		return -EINVAL;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 93) &&                          \
	LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 6)
	pf_uld_check_file = (typeof(pf_uld_check_file))lookup_symbol("uld_check_"
																 "file");
	if (!pf_uld_check_file)
	{
		pr_err("fail to lookup symbol 'uld_check_file'\n");
		return -EINVAL;
	}
#endif

	if (register_misc_dev())
	{
		pr_err("err register misc device\n");
		return -EFAULT;
	}

	pr_debug("retreat_init done\n");
	return 0;
}

static void __exit retreat_exit(void)
{
	misc_deregister(&misc);
	pr_debug("retreat_exit done\n");
}

module_init(retreat_init);
module_exit(retreat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("uniontech.com");
MODULE_DESCRIPTION("a module helping to retreat accidentally deleted files(if "
				   "it's still referenced by any process)");