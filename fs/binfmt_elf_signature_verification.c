/*
 * binfmt_elf_signature_verification.c
 *
 * Copyright (C) 2020 Jingtang Zhang, Hua Zong
 *
 * binfmt_elf_signature_verification ...
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/magic.h>
#include <linux/binfmts.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/string_helpers.h>
#include <linux/file.h>
#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#include "internal.h"

#ifdef DEBUG
# define USE_DEBUG 1
#else
# define USE_DEBUG 0
#endif

/*
 * \brief The loader of Signature Verification.
 */
static int load_elf_signature_verification_binary(struct linux_binprm *bprm)
{
	int retval;
	int verify_pass;

	printk("Start to verify the signature ...\n");

	/* Verifying the signature here. */
	verify_pass = 1;

	if (verify_pass) {
		printk("Verifying pass ...\n");
		retval = -ENOEXEC;
	} else {
		printk("Verifying falied ...\n");
		retval = 0;
	}
        
	return retval;
}

/*
 * \brief Register a new elf_binfmt for Signature Verification.
 */
static struct linux_binfmt elf_signature_verification_format = {
	.module = THIS_MODULE,
	.load_binary = load_elf_signature_verification_binary,
};

static int __init init_elf_signature_verification_binfmt(void)
{
	register_binfmt(&elf_signature_verification_format);
	return 0;
}

static void __exit exit_elf_signature_verification_binfmt(void)
{
	unregister_binfmt(&elf_signature_verification_format);
}

core_initcall(init_elf_signature_verification_binfmt);
module_exit(exit_elf_signature_verification_binfmt);
MODULE_LICENSE("GPL");
MODULE_ALIAS_FS("binfmt_elf_signature_verification");
