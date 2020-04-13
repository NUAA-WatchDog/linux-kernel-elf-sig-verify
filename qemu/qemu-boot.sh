# config KERNEL and IMAGE
source env.bash

# boot qemu
qemu-system-x86_64 \
  -kernel $KERNEL/arch/x86_64/boot/bzImage \
  -append "console=ttyS0 root=/dev/sda debug earlyprintk=serial slub_debug=QUZ"\
  -hda $IMAGE/stretch.img \
  -nographic \
  -m 2G \
  -smp 2 \
  -pidfile vm.pid \
  2>&1 | tee vm.log
