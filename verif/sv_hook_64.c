/*
 * \brief This module is used to verif the signature of binary executable program in Linux.
 */
 
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <asm/pgtable.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>

typedef asmlinkage long (*orig_execve)(const char __user *filename,
    const char __user *const __user *argv, const char __user *const __user *envp);

orig_execve old_execve = NULL;

unsigned long * sys_call_table = NULL;

/*
 * \brief New sys_execve for signature verifier.
 */
asmlinkage long svHookExecve(const char __user *filename,
    const char __user *const __user *argv, const char __user *const __user *envp)
{
  printk("+ svHookExecve been called !");
  return old_execve(filename, argv, envp);
}

/*
 * \brief Catch the sys_call_table's address.
 */
static unsigned long svGetSysCallTable(void)
{  
	unsigned long lookup_addr;
 
	lookup_addr = (void *)kallsyms_lookup_name("sys_call_table");

  if (NULL == lookup_addr) {
    printk(KERN_ERR "- Couldn't look up sys_call_table\n");
    return 0;
  }
	
	// printk("Found sys_call_table: %p", (void *) lookup_addr);
		
  return lookup_addr;
}

/*
 * \brief Initial svHook module.
 */
static int __init svHookInit(void) {

  printk("+ Loading svHookExecve module\n");

  sys_call_table = (unsigned long *) svGetSysCallTable();

  if (0 == (unsigned long) sys_call_table) {
    printk(KERN_ERR "- Catch sys_call_table failed !\n");
    return -1;
  }

  printk("+ Found sys_call_table at %p!\n", sys_call_table);

  // TMP // sys_call_mask = (unsigned long) sys_call_table;
  // TMP // sys_call_mask |= 0xffffffff00000000;
  // TMP // sys_call_table = (unsigned long *) sys_call_mask;

  old_execve = ((unsigned long *) sys_call_table)[__NR_execve];

  write_cr0(read_cr0() & ~0x10000);

  printk("+ Hook the __NR_execve to svHookExecve !\n");
 
  ((unsigned long *) sys_call_table)[__NR_execve]= (unsigned long) svHookExecve;

  write_cr0(read_cr0() | 0x10000);
 
  printk("+ Sys_execve hooked!\n");
 
  return 0;
}

/*
 * \brief Exit svHook module.
 */
static void __exit svHookExit(void)
{
  printk("+ Unloading svHookExecve module\n");

  if(old_execve != NULL) {

    write_cr0(read_cr0() & ~0x10000);

    ((unsigned long *) sys_call_table)[__NR_execve] = (unsigned long) old_execve;

    write_cr0(read_cr0() | 0x10000);
  }
  printk("+ Sys_execve unhooked!\n");
  return;
}
 
module_init(svHookInit);
module_exit(svHookExit);
 
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Howard");
MODULE_DESCRIPTION("This module is used to verif the signature of binary executable program in Linux.");
MODULE_ALIAS("Signature Verifier");
