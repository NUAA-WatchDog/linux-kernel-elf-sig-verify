/********************************************************************
 *
 * Copyright (C) 2020, Jingtang Zhang, Hua Zong
 * 
 * binfmt_elf_signature_verification.c
 *
 * Verify the ELF's signature with built-in key-ring.
 * If the signature is correct, return -ENOEXEC to invoke real
 * ELF binary handler; else, return the error code to do_execve()
 * and avoid the ELF being executed.
 * 
 ********************************************************************/

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

/* That's for binfmt_elf_fdpic to deal with */
#ifndef elf_check_fdpic
#define elf_check_fdpic(ex) false
#endif

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN	PAGE_SIZE
#endif

enum verify_signature_e { VPASS, VFAIL, VSKIP };

unsigned char SIG_SCN_SUFFIX[] = "_sig";

struct linux_sfmt {
	unsigned char *s_name;
	int		s_nlen;
};

// struct elf_signature {
// 	u8	algo;		/* Public-key crypto algorithm [0] */
// 	u8	hash;		/* Digest algorithm [0] */
// 	u8	id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
// 	u8	signer_len;	/* Length of signer's name [0] */
// 	u8	key_id_len;	/* Length of key identifier [0] */
// 	u8	__pad[3];
// 	__be32	sig_len;	/* Length of signature data */
// };

struct scn_checklist {
	unsigned char s_name[8];
	int s_nlen;
	int s_check;
};

static int update_checklist(struct scn_checklist *scn_cklt, int cklt_len,
			unsigned char *sname)
{
	int i, retval = 1;
	for (i = 0; i < cklt_len; i++) {
		if (!memcmp(scn_cklt[i].s_name, sname, scn_cklt[i].s_nlen)) {
			scn_cklt[i].s_check = 1;
			retval = 0;
			goto out;
		}
	}
out:
	return retval;
}

static int lookup_checklist(struct scn_checklist *scn_cklt, int cklt_len)
{
	int i, retval = 0;
	for (i = 0; i < cklt_len; i++) {
		if (0 == scn_cklt[i].s_check) {
			printk(" Section '%s' must be signed !\n", scn_cklt[i].s_name);
			retval = 1;
			// goto out;
		}
	}
// out:
	return retval;
}

/**
 * load_elf_shdrs() - load ELF section headers
 * 
 * Loads ELF section headers from the binary file elf_file, which has the ELF
 * header pointed to by elf_ex, into a newly allocated array. The caller is
 * responsible for freeing the allocated data. Returns an ERR_PTR upon failure.
 * 
 * @elf_ex:   ELF header of the binary whose section headers shold be loaded.
 * @elf_file: the opened ELF binary file.
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

	elf_shdata = vmalloc(size);
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
		vfree(elf_shdata);
		elf_shdata = NULL;
	}
	return elf_shdata;
}
/*}}}*/

/**
 * load_elf_sdata() - load ELF section data
 * 
 * Loads ELF section data from the binary file elf_file.
 * 
 * @elf_shdata: ELF section header table.
 * @elf_file: The opened ELF binary file.
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
	elf_sdata = vmalloc(size);
	if (!elf_sdata)
		goto out_ret;

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
		vfree(elf_sdata);
		elf_sdata = NULL;
	}
out_ret:
	return elf_sdata;
}
/*}}}*/

/**
 * sub_str()
 * 
 * Split a string by a terminate flag.
 * 
 * @str: The string to be split.
 * @stop_flag: A flag indicating where to stop.
 * @len: Return the length of the sub-string.
 */
/*{{{*/	// sub_str
static unsigned char *sub_str(unsigned char *str,
				unsigned char stop_flag,
				int *len)
{
	int i = 0, j;
	unsigned char *substr = NULL;

	while (stop_flag != str[i]) i++;

	*len = i;

	substr = vmalloc(++i);
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
 * scn_name_cmp() - memory compare for section names.
 * 
 * Firstly, compare the prefix of signed_scn_name and scn_name.
 * If signed_scn_name[prefix] == scn_name[prefix], then compare the suffix,
 * if signed_scn_name[suffix] == "_sig", comparison pass.
 * 
 * @scn_name: The original section name, e.g. ".text".
 * @scn_name_len: The length of original section name.
 * @signed_scn_name: The signed section name, e.g. ".text_sig".
 * @signed_scn_name_len: The length of signed section name.
 *
 */
/*{{{*/	// scn_name_cmp
static int scn_name_cmp(unsigned char *scn_name, int scn_name_len,
			unsigned char *signed_scn_name, int signed_scn_name_len)
{
	int retval = 1;
	
	/* Default -> signed_scn_name_len > scn_name_len */
	if ((sizeof(SIG_SCN_SUFFIX) - 1) != (signed_scn_name_len - scn_name_len))
		goto out;
	if (memcmp(signed_scn_name, scn_name, scn_name_len))
		goto out;
	if (memcmp(signed_scn_name + scn_name_len,
			SIG_SCN_SUFFIX, sizeof(SIG_SCN_SUFFIX) - 1))
		goto out;

	/* Success! */
	retval = 0;
out:
	return retval;
}
/*}}}*/

/**
 * 
 * verify_scn_signature() - verify the section signature.
 * 
 * Use verify_pkcs7_signature(...) to verify the signature.
 * 
 * @scn_data: Data of original section.
 * @scn_data_len: Length of original section data.
 * @sig_scn_data: Data of signature section.
 * @sig_scn_data_len: Length of signature section data.
 *
 */
/*{{{*/	// verify_scn_signature
static int verify_scn_signature(unsigned char *scn_data, int scn_data_len, 
				unsigned char *sig_scn_data, int sig_scn_data_len)
{
	int retval;

	retval = verify_pkcs7_signature(scn_data, scn_data_len,
					sig_scn_data, sig_scn_data_len,
					NULL, VERIFYING_MODULE_SIGNATURE, NULL, NULL);
	printk("verify_pkcs7_signature return value: %d\n", retval);
	return retval;
}
/*}}}*/

/**
 * load_elf_signature_verification_binary() - ...
 * 
 * The loader function of ELF signature verification.
 * 
 * @bprm: the bin program handler
 */
static int load_elf_signature_verification_binary(struct linux_binprm *bprm)
{
	int retval, index, i, j;
	int elf_slen, elf_sslen, elf_snum;
	enum verify_signature_e verify_e = VFAIL;
	unsigned char *elf_strtab, *elf_sname, *elf_sdata, *elf_ssdata;
	// loff_t pos;
	struct elf_shdr *elf_shptr, *elf_shdata;
	struct {
		struct elfhdr elf_ex;
		struct elfhdr interp_elf_ex;
	} *loc;
	struct linux_sfmt *elf_sarr;

	struct scn_checklist scn_cklt[] = {
		{".text", 5, 0},
		// {".data", 5, 0}
	};
	
	/* We don't need to verify the system elf files */
	if (!memcmp(bprm->interp, "/bin/", 5) ||
		!memcmp(bprm->interp, "/lib/", 5) ||
		!memcmp(bprm->interp, "/etc/", 5) ||
		!memcmp(bprm->interp, "/sbin/", 6) ||
		// !memcmp(bprm->interp, "/usr/bin/", 9) ||
		// !memcmp(bprm->interp, "/usr/sbin/", 10) ||
		!memcmp(bprm->interp, "/usr/", 5) ||
		!memcmp(bprm->interp, "/tmp/", 5) ||
		!memcmp(bprm->interp, "/var/", 5)) {
		verify_e = VSKIP;
		goto out_ret;
	}

	printk("Start verify '%s' ...", bprm->interp);

	loc = vmalloc(sizeof(*loc));
	if (!loc) {
		retval = -ENOMEM;
		goto out_ret;
	}

	/* Get the exec-header */
	loc->elf_ex = *((struct elfhdr *) bprm->buf);

	retval = -ENOEXEC;
	/* First of all, some simple consistency checks */
	if (memcmp(loc->elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out_free_loc;
	if (loc->elf_ex.e_type != ET_EXEC && loc->elf_ex.e_type != ET_DYN)
		goto out_free_loc;
	if (!elf_check_arch(&loc->elf_ex))
		goto out_free_loc;
	if (elf_check_fdpic(&loc->elf_ex))
		goto out_free_loc;
	if (!bprm->file->f_op->mmap)
		goto out_free_loc;
	
	/* Load ELF's section header table */
	elf_shdata = load_elf_shdrs(&loc->elf_ex, bprm->file);
	if (!elf_shdata) {
		retval = -ENOMEM;
		goto out_free_loc;
	}
	
	if (SHN_UNDEF == loc->elf_ex.e_shstrndx) {
		retval = -EBADMSG;
		goto out_free_shdata;
	}

	/* Load ELF's String Table section */
	elf_shptr = elf_shdata + loc->elf_ex.e_shstrndx;
	elf_strtab = load_elf_sdata(elf_shptr, bprm->file);
	if (!elf_strtab) {
		retval = -ENOMEM;
		goto out_free_shdata;
	}

	elf_snum = loc->elf_ex.e_shnum;
	elf_sarr = vmalloc(sizeof(struct linux_sfmt) * elf_snum);
	if (!elf_sarr) {
		retval = -ENOMEM;
		goto out_free_strtab;
	}

	elf_shptr = elf_shdata;

	/* Gather the name of each section. */
	for (i = 0; i < elf_snum; i++) {
		index = elf_shptr->sh_name;
		elf_sname = sub_str(&elf_strtab[index], '\0', &elf_slen);
		elf_sarr[i].s_name = elf_sname;
		elf_sarr[i].s_nlen = elf_slen;
		printk("Section\t name '%s'\t len %d\n", elf_sarr[i].s_name, elf_sarr[i].s_nlen);
		elf_shptr++;
	}

	printk("Start to verify the signature ...\n");
	
	/* 
	 * Find out the signature sections with suffix '_sig',
	 * then verify the signature.
	 */
	for (i = 0; i < elf_snum; i++) {
		for (j = 0; j < elf_snum; j++) {

			/**
			 * Early exit if such case is impossible to happen:
			 * 		len(".text") < len(".text_sig")
			 * where [i] stand for ".text", [j] stand for ".text_sig".
			 */
			if (elf_sarr[i].s_nlen >= elf_sarr[j].s_nlen) {
				continue;
			}

			/* The section should be matched with its signature section. */
			if (scn_name_cmp(elf_sarr[i].s_name, elf_sarr[i].s_nlen,
					elf_sarr[j].s_name, elf_sarr[j].s_nlen)) {
				continue;
			}

			/* 
			 * Found two sections with matching name, e.g. ".text" and
			 * ".text_sig". Then, we need to load the data of two sections.
			 */
			printk("Find two matching sections : %s %s",
					elf_sarr[i].s_name, elf_sarr[j].s_name);

			/* Load the original data section. */
			elf_shptr = elf_shdata + i;
			elf_slen = elf_shptr->sh_size;
			elf_sdata = load_elf_sdata(elf_shptr, bprm->file);
			if (!elf_sdata) {
				retval = -ENOMEM;
				goto out_free_sarr;
			}
			
			/* Load the signature data section. */
			elf_shptr = elf_shdata + j;
			elf_sslen = elf_shptr->sh_size;
			elf_ssdata = load_elf_sdata(elf_shptr, bprm->file);
			if (!elf_ssdata) {
				retval = -ENOMEM;
				goto out_free_sdata;
			}

			/* Verify the signature. */
			retval = verify_scn_signature(elf_sdata, elf_slen,
						elf_ssdata, elf_sslen);
			if (retval) {
				goto out_free_ssdata;
			}

			/* Update check list status. */
			update_checklist(scn_cklt,
					sizeof(scn_cklt) / sizeof(struct scn_checklist),
					elf_sarr[i].s_name);

			vfree(elf_sdata);
			vfree(elf_ssdata);
			elf_sdata = NULL;
			elf_ssdata = NULL;
		}
	}
	
	/* Make sure all signature sections are successfully verified. */
	if (!lookup_checklist(scn_cklt,
			sizeof(scn_cklt) / sizeof(struct scn_checklist))) {
		verify_e = VPASS;
	} else {
		retval = -ENOKEY;
		verify_e = VFAIL;
	}
	
	goto out_free_sarr;

out_ret:
	if (VPASS == verify_e) {
		printk("Verifying pass ...\n");
		retval = -ENOEXEC;
	} else if (VFAIL == verify_e) {
		printk("Verifying falied ...\n");
	} else
		retval = -ENOEXEC;

	return retval;
	
out_free_ssdata:
	vfree(elf_ssdata);
out_free_sdata:
	vfree(elf_sdata);
out_free_sarr:
	for (i = 0; i < elf_snum; i++) {
		if (!elf_sarr[i].s_name) {
			vfree(elf_sarr[i].s_name);
		}
	}
	vfree(elf_sarr);
out_free_strtab:
	vfree(elf_strtab);
out_free_shdata:
	vfree(elf_shdata);
out_free_loc:
	vfree(loc);
	goto out_ret;
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
