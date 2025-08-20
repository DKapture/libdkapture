/**
 * this module is used for detecting malicious processes who first delete their
 * program file at the running start to avoid being scanned by system security
 * software.
 *
 * when process delete their program file, we can retreat it back through the
 * misc device created by this module, simplely by writing the pids of the
 * malicious processes to the misc device, then their program files will be
 * retreated back to the /tmp directory, named by their pid, as for this, the
 * caller should be responsible for checking files already named in that pid
 * in the /tmp directory。
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
#include <linux/miscdevice.h>

static rwlock_t *ptasklist_lock;
static struct miscdevice misc;

static int do_nothing(struct kprobe *p, struct pt_regs *regs)
{
	(void)p;
	(void)regs;
	return 0;
}

static typeof(kallsyms_lookup_name) *lookup_symbol;
static typeof(get_task_exe_file) *get_task_exe;

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
	}

	kfree(kbuf);
	return ret;
}

static int kdump_task_exe(pid_t pid)
{
	int ret;
	char kbuf[16] = {};
	struct file *out_file = NULL;
	struct file *exe = NULL;
	struct task_struct *p;

	read_lock(ptasklist_lock);
	for_each_process(p)
	{
		if (p->pid == pid)
		{
			break;
		}
	}
	if (p != &init_task)
	{
		exe = get_task_exe(p);
	}
	read_unlock(ptasklist_lock);
	if (!exe)
	{
		return -ENOENT;
	}

	snprintf(kbuf, sizeof(kbuf), "/tmp/%d", pid);

	out_file = filp_open(kbuf, O_CREAT | O_WRONLY, 0744);
	if (!out_file)
	{
		ret = -EFAULT;
		goto exit;
	}

	ret = kfile_copy(exe, out_file);
	if (ret)
	{
		goto exit;
	}

exit:
	if (out_file)
	{
		filp_close(out_file, NULL);
	}
	fput(exe);
	return ret;
}

static ssize_t
misc_write(struct file *fp, const char *__user buf, size_t bsz, loff_t *off)
{
	if (bsz < sizeof(pid_t))
	{
		return -EINVAL;
	}

	long ret;
	char *kbuf = NULL;
	pid_t *pids;

	if (bsz > PATH_MAX)
	{
		pr_err("buf no larger than 4096 once\n");
		return -E2BIG;
	}

	kbuf = kmalloc(PATH_MAX, GFP_KERNEL);
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

	pids = (pid_t *)kbuf;
	for (uint32_t i = 0; i < bsz / sizeof(pid_t); i++)
	{
		ret = kdump_task_exe(pids[i]);
		if (ret)
		{
			goto exit;
		}
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
	misc.name = "dump-task-exe";
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

	get_task_exe = (typeof(get_task_exe))lookup_symbol("get_task_exe_file");
	if (!get_task_exe)
	{
		pr_err("fail to lookup symbol 'get_task_exe_file'\n");
		return -EFAULT;
	}

	ptasklist_lock = (typeof(ptasklist_lock))lookup_symbol("tasklist_lock");
	if (!ptasklist_lock)
	{
		pr_err("fail to lookup symbol 'tasklist_lock'\n");
		return -EINVAL;
	}

	if (register_misc_dev())
	{
		pr_err("err register misc device\n");
		return -EFAULT;
	}

	pr_info("retreat_init done\n");
	return 0;
}

static void __exit retreat_exit(void)
{
	misc_deregister(&misc);
	pr_info("retreat_exit done\n");
}

module_init(retreat_init);
module_exit(retreat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("uniontech.com");
MODULE_DESCRIPTION("a module helping to retreat exe file of process");