Building and Running libs2e
===========================

1. Build S2E as usual 

   ```
   make -f ../s2e/Makefile all-release all-debug
   ```
   
2. Build qemu from https://github.com/S2E/qemu (You will need to use this qemu further)
   
   ```
   git clone https://github.com/S2E/qemu
   mkdir s2e-qemu-build
   cd s2e-qemu-build
   ../s2e-qemu/configure --enable-debug --disable-werror --target-list="i386-softmmu x86_64-softmmu" --disable-docs
   make
   export QEMU_BUILD=/path/to/qemu-build
   ```
   
3. Run libs2e in non-S2E mode
   
   ```
   LD_PRELOAD=${S2E_BUILD}/libs2e-release/x86_64-softmmu/libs2e.so \
       ${QEMU_BUILD}/x86_64-softmmu/qemu-system-x86_64 -drive file=windows7.raw.s2e,cache=writeback,format=s2e -m 2G -enable-kvm
   ```
   
4. Run libs2e in S2E mode
   
   ```
   export S2E_CONFIG=s2e-config.lua
   export S2E_SHARED_DIR=${S2E_BUILD}/libs2e-release/x86_64-s2e-softmmu/

   LD_PRELOAD=${S2E_BUILD}/libs2e-release/x86_64-s2e-softmmu/libs2e.so \
       ${QEMU_BUILD}/x86_64-softmmu/qemu-system-x86_64 -drive file=windows7.raw.s2e,cache=writeback,format=s2e -m 2G -enable-kvm -net none -loadvm ready
   ```
