/********************************************************************
 *
 * Copyright (C) 2020 Jingtang Zhang, Hua Zong
 * 
 * binfmt_elf_signature_verification.c
 *
 * Verify the ELF's signature with built-in key-ring.
 * If the signature is correct, return -ENOEXEC to invoke real
 * ELF binary handler; else, return the error code to do_execve()
 * and avoid the ELF being executed.
 * 
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
#include <linux/elf.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#include <linux/verification.h>

#include "internal.h"

/* That's for binfmt_elf_fdpic to deal with */
#ifndef elf_check_fdpic
#define elf_check_fdpic(ex) false
#endif

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN	PAGE_SIZE
#endif

#define SIG_SUFFIX_SIZE 4

struct linux_sfmt {
	// int 		s_id;
	unsigned char * s_name;
	int		s_nlen;
	// unsigned char	s_sig;
};

struct elf_signature {
	u8	algo;		/* Public-key crypto algorithm [0] */
	u8	hash;		/* Digest algorithm [0] */
	u8	id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
	u8	signer_len;	/* Length of signer's name [0] */
	u8	key_id_len;	/* Length of key identifier [0] */
	u8	__pad[3];
	__be32	sig_len;	/* Length of signature data */
};

enum verify_signature_e { VPASS, VFAIL, VSKIP };

/**
 * load_elf_shdrs() - load ELF section headers
 * @elf_ex:   ELF header of the binary whose section headers shold be loaded
 * @elf_file: the opened ELF binary file
 *
 * Loads ELF section headers from the binary file elf_file, which has the ELF
 * header pointed to by elf_ex, into a newly allocated array. The caller is
 * responsible for freeing the allocated data. Returns an ERR_PTR upon failure.
 */
/*{{{*/	// load_elf_shdrs
static struct elf_shdr *load_elf_shdrs(struct elfhdr *elf_ex,
				       struct file *elf_file)
{
	struct elf_shdr *elf_shdata = NULL;
	int retval, size, err = -1;
	loff_t pos = elf_ex->e_shoff;

	/*
	 * If the size of this structure has changed, then punt, since
	 * we will be doing the wrong thing.
	 */
	if (elf_ex->e_shentsize != sizeof(struct elf_shdr))
		goto out;

	/* Sanity check the number of section headers... */
	if (elf_ex->e_shnum < 1 ||
		elf_ex->e_shnum > 65536U / sizeof(struct elf_shdr))
		goto out;

	/* ...and their total size. */
	size = sizeof(struct elf_shdr) * elf_ex->e_shnum;
	if (size > ELF_MIN_ALIGN)
		goto out;

	elf_shdata = kmalloc(size, GFP_KERNEL);
	if (!elf_shdata)
		goto out;

	/* Read in the section headers */
	retval = kernel_read(elf_file, elf_shdata, size, &pos);
	if (retval != size) {
		err = (retval < 0) ? retval : -EIO;
		goto out;
	}

	/* Success! */
	err = 0;
out:
	if (err) {
		kfree(elf_shdata);
		elf_shdata = NULL;
	}
	return elf_shdata;
}
/*}}}*/

/**
 * load_elf_strtab() - load ELF String Table
 * @elf_shdata:   ELF section header table
 * @elf_file: the opened ELF binary file
 * @elf_strndx: The String Table index in the section header table
 *
 * Loads ELF section String Table from the binary file elf_file.
 */
/*{{{*/	// load_elf_strtab
static unsigned char *load_elf_strtab(struct elf_shdr *elf_shdata,
					struct file *elf_file,
					Elf64_Half elf_strndx)
{
	int size, retval = -EIO, err = -1;
	struct elf_shdr *elf_shstr;
	unsigned char *elf_strtab = NULL;
	loff_t pos;
	
	/* If there is no String Table in this ELF file, return NULL */
	if (SHN_UNDEF == elf_strndx)
		goto out_ret;

	/* Get the section String Table entry */
	elf_shstr = elf_shdata + elf_strndx;
	
	/* If the String Table is empty, return NULL */
	if (SHT_NOBITS == elf_shstr->sh_offset)
		goto out_ret;

	pos = elf_shstr->sh_offset;
	size = elf_shstr->sh_size;
	elf_strtab = kmalloc(size, GFP_KERNEL);
	if (!elf_strtab)
		goto out;

	/* Read the secton String Table into new kernel memory space */
	retval = kernel_read(elf_file, elf_strtab, size, &pos);
	if (retval != size) {
		err = (retval < 0) ? retval : -EIO;
		goto out;
	}

	/* Success! */
	err = 0;
out:
	if (err) {
		kfree(elf_strtab);
		elf_strtab = NULL;
	}
out_ret:
	return elf_strtab;
}
/*}}}*/

/**
 * load_elf_sdata() - load ELF section data
 * @elf_shdata:   ELF section header table
 * @elf_file: the opened ELF binary file
 *
 * Loads ELF section data from the binary file elf_file.
 */
/*{{{*/	// load_elf_sdata
static unsigned char *load_elf_sdata(struct elf_shdr *elf_shdata,
					struct file *elf_file)
{
	int size, retval = -EIO, err = -1;
	unsigned char *elf_sdata = NULL;
	loff_t pos;
	
	/* If the section is empty, return NULL */
	if (SHT_NOBITS == elf_shdata->sh_offset)
		goto out_ret;

	pos = elf_shdata->sh_offset;
	size = elf_shdata->sh_size;
	elf_sdata = kmalloc(size, GFP_KERNEL);
	if (!elf_sdata)
		goto out;

	/* Read the secton data into new kernel memory space */
	retval = kernel_read(elf_file, elf_sdata, size, &pos);
	if (retval != size) {
		err = (retval < 0) ? retval : -EIO;
		goto out;
	}

	/* Success! */
	err = 0;
out:
	if (err) {
		kfree(elf_sdata);
		elf_sdata = NULL;
	}
out_ret:
	return elf_sdata;
}
/*}}}*/

/**
 * sub_str() - subtract section string table
 * @str: The string that needed subtraction
 * @subfg: This is a flag, tell where to stop
 * @len: Return length of the subtraction string
 *
 * Subtract the input string to a new sub-str.
 */
/*{{{*/	// sub_str
static unsigned char * sub_str(unsigned char * str,
				unsigned char subfg,
				int * len)
{
	int i = 0, j;
	unsigned char * substr = NULL;

	while (subfg != str[i]) i++;

	*len = i;

	substr = kmalloc(++i, GFP_KERNEL);
	if (!substr)
		goto out;

	for (j = 0; j < i; j++)
		substr[j] = str[j];
	substr[i] = '\0';
out:
	return substr;
}
/*}}}*/

/**
 * memcmp_sig() - memory compare for signature
 * @sstr: The longer string 
 * @sslen: The length of longer string 
 * @dstr: The shorter string 
 * @sslen: The length of shorter string 
 *
 * Firstly, compare the prefix of sstr and dstr,
 * if sstr[prefix]=dstr[prefix], then compare the suffix,
 * if sstr[suffix]="_sig", compare pass.
 */
/*{{{*/	// memcmp_sig
static int memcmp_sig(unsigned char * sstr, int sslen,
			unsigned char * dstr, int dslen)
{
	int retval = 1;
	unsigned char sig_suffix[SIG_SUFFIX_SIZE + 1] = "_sig";

	/* Default -> sslen > dslen */
	if (SIG_SUFFIX_SIZE != (sslen - dslen))
		goto out;
	if (memcmp(sstr, dstr, dslen))
		goto out;
	if (memcmp(sstr + dslen, sig_suffix, SIG_SUFFIX_SIZE))
		goto out;

	/* Success! */
	retval = 0;
out:
	return retval;
}
/*}}}*/

static unsigned char * sign_elf_section(unsigned char *elf_sdata,
					int ssize)
{
	int i;
	unsigned char *sig_sdata = NULL;
	
	sig_sdata = kmalloc(ssize, GFP_KERNEL);
	if (!sig_sdata)
		goto out;
	/* Sign the section here */
	for (i = 0; i < ssize; i++)
		sig_sdata[i] = 0xff;
out:
	return sig_sdata;
}

static int verify_elf_signature(unsigned char *old_ssdata, int old_slen, 
				unsigned char *new_ssdata, int new_slen)
{
	int retval;
	size_t sig_len = new_slen - sizeof(struct elf_signature);

	retval = verify_pkcs7_signature(old_ssdata, old_slen,
					new_ssdata, sig_len, NULL,
					VERIFYING_MODULE_SIGNATURE, NULL, NULL);
	printk("verify_pkcs7_signature return value: %d\n", retval);
	return retval;
}

/**
 * load_elf_signature_verification_binary() - ...
 * @bprm: the bin program handler
 *
 * The loader of Signature Verification.
 */
static int load_elf_signature_verification_binary(struct linux_binprm *bprm)
{
	int retval, index, i, j, len;
	int elf_slen, elf_sslen;
	enum verify_signature_e verify_e = VFAIL;
	unsigned char *elf_strtab, *elf_snstr, *elf_sdata, *elf_ssdata;
	// loff_t pos;
	struct elf_shdr *elf_spnt, *elf_shdata;
	struct {
		struct elfhdr elf_ex;
		struct elfhdr interp_elf_ex;
	} *loc;
	struct linux_sfmt *elf_sarr;
	
	/* We don't need to verify the system elf files */
	if (!memcmp(bprm->filename, "/bin/", 5) || !memcmp(bprm->filename, "/lib/", 5) ||
		!memcmp(bprm->filename, "/etc/", 5) || !memcmp(bprm->filename, "/sbin/", 6) ||
		!memcmp(bprm->filename, "/usr/bin/", 9) || !memcmp(bprm->filename, "/usr/sbin/", 10) ||
		!memcmp(bprm->filename, "/usr/lib/", 9)) {
		// printk("Jump filename : %s", bprm->filename);
		verify_e = VSKIP;
		retval = -ENOEXEC;
		goto out_ret;
	} else {
		printk("Get filename : %s", bprm->filename);
	}

	loc = kmalloc(sizeof(*loc), GFP_KERNEL);
	if (!loc) {
		retval = -ENOMEM;
		goto out_ret;
	}

	/* Get the exec-header */
	loc->elf_ex = *((struct elfhdr *)bprm->buf);

	retval = -ENOEXEC;
	/* First of all, some simple consistency checks */
	if (memcmp(loc->elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out;
	if (loc->elf_ex.e_type != ET_EXEC && loc->elf_ex.e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(&loc->elf_ex))
		goto out;
	if (elf_check_fdpic(&loc->elf_ex))
		goto out;
	if (!bprm->file->f_op->mmap)
		goto out;
	
	/* Load ELF section header table */
	elf_shdata = load_elf_shdrs(&loc->elf_ex, bprm->file);
	if (!elf_shdata)
		goto out;
	
	if (SHN_UNDEF == loc->elf_ex.e_shstrndx)
		goto out_free_shdata;

	/* Load ELF section String Table */
	elf_spnt = elf_shdata + loc->elf_ex.e_shstrndx;
	elf_strtab = load_elf_sdata(elf_spnt, bprm->file);
	if (!elf_strtab)
		goto out_free_shdata;

	elf_sarr = kmalloc(sizeof(struct linux_sfmt) * loc->elf_ex.e_shnum, GFP_KERNEL);
	if (!elf_sarr)
		goto out_free_strtab;

	elf_spnt = elf_shdata;

	for (i = 0; i < loc->elf_ex.e_shnum; i++) {
		index = elf_spnt->sh_name;
		elf_snstr = sub_str(&elf_strtab[index], '\0', &len);
		// if (!elf_snstr)
		// 	goto out_free_sarr;
		elf_sarr[i].s_name = elf_snstr;
		elf_sarr[i].s_nlen = len;
		printk("Section\t name '%s'\t len %d\n", elf_sarr[i].s_name, elf_sarr[i].s_nlen);
		elf_spnt++;
	}

	printk("Start to verify the signature ...\n");
	
	/* 
	 * Find out the signature sections with suffix '_sig',
	 * then verify the signature.
	 */
	for (i = 0; i < loc->elf_ex.e_shnum; i++) {

		for (j = 0; j < loc->elf_ex.e_shnum; j++) {

			/* Choose the sig section to be the first dim */
			if (elf_sarr[i].s_nlen <= elf_sarr[j].s_nlen) {
				continue;
			}
			if (memcmp_sig(elf_sarr[i].s_name, elf_sarr[i].s_nlen,
					elf_sarr[j].s_name, elf_sarr[j].s_nlen)) {
				continue;
			}
			/* 
			 * Find two sections with matching name (eg. sec and sec_sig).
			 * Firstly, we need to load the two sections data,
			 * and use pkcs7 to verify the signature is vaild or not.
			 */

			printk("Find two matching sections : %s %s",
					elf_sarr[i].s_name, elf_sarr[j].s_name);

			// Step1. Load the sec data
			elf_spnt = elf_shdata + j;
			elf_slen = elf_spnt->sh_size;
			elf_sdata = load_elf_sdata(elf_spnt, bprm->file);
			if (!elf_sdata) {
				goto out_free_sarr;
			}
			
			// Step2. Load the sec_sig data
			elf_spnt = elf_shdata + i;
			elf_sslen = elf_spnt->sh_size;
			elf_ssdata = load_elf_sdata(elf_spnt, bprm->file);
			if (!elf_ssdata) {
				goto out_free_sdata;
			}

			// Step3. Run verify_elf_signature to verify the signature is valid or not
			retval = verify_elf_signature(elf_sdata, elf_slen, elf_ssdata, elf_sslen);
			if (retval) {
				goto out_free_ssdata;
			}

			kfree(elf_sdata);
			// kfree(sig_sdata);
			kfree(elf_ssdata);
			elf_sdata = NULL;
			// sig_sdata = NULL;
			elf_ssdata = NULL;
		}
	}

	/* Success! */
	verify_e = VPASS;

out:
	kfree(loc);
out_ret:
	if (VPASS == verify_e) {
		printk("Verifying pass ...\n");
		retval = -ENOEXEC;
	} else if (VFAIL == verify_e) {
		printk("Verifying falied ...\n");
		// retval = -ENOMEM;
	} else
		retval = -ENOEXEC;

	return retval;
	
out_free_ssdata:
	kfree(elf_ssdata);
// out_free_sig_sdata:
// 	kfree(sig_sdata);
out_free_sdata:
	kfree(elf_sdata);
out_free_sarr:
	for (i = 0; i < loc->elf_ex.e_shnum; i++) {
		kfree(elf_sarr[i].s_name);
	}
	kfree(elf_sarr);
out_free_strtab:
	kfree(elf_strtab);
out_free_shdata:
	kfree(elf_shdata);
	goto out;
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
