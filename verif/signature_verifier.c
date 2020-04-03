/*
 * \brief This module is used to verif the signature of binary executable program in Linux.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("Dual BSD/GPL");

static int signature_verifier_init(void) {
  printk(KERN_ALERT "The signature verifier of binary executable program in Linux is ready !");
  return 0;
}

static void signature_verifier_exit(void) {
  printk(KERN_ALERT "The signature verifier of binary executable program in Linux has been uninstalled !");
}

module_init(signature_verifier_init);
module_exit(signature_verifier_exit);

MODULE_AUTHOR("Howard");
MODULE_DESCRIPTION("This module is used to verif the signature of binary executable program in Linux.");
MODULE_ALIAS("Signature Verifier");
