/// Copyright (C) 2019  Cyberhaven
/// Copyrights of all contributions belong to their respective owners.
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Library General Public
/// License as published by the Free Software Foundation; either
/// version 2 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Library General Public License for more details.
///
/// You should have received a copy of the GNU Library General Public
/// License along with this library; if not, see <http://www.gnu.org/licenses/>.

#ifndef LIBCPU_i386_CPUID
#define LIBCPU_i386_CPUID

#include <inttypes.h>
#include <libcpu-log.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cpuid_t {
    uint32_t cpuid_level;
    uint32_t cpuid_vendor1;
    uint32_t cpuid_vendor2;
    uint32_t cpuid_vendor3;
    uint32_t cpuid_version;
    uint32_t cpuid_features;
    uint32_t cpuid_ext_features;
    uint32_t cpuid_xlevel;
    uint32_t cpuid_model[12];
    uint32_t cpuid_ext2_features;
    uint32_t cpuid_ext3_features;
    uint32_t cpuid_apic_id;
    int cpuid_vendor_override;
    /* Store the results of Centaur's CPUID instructions */
    uint32_t cpuid_xlevel2;
    uint32_t cpuid_ext4_features;

    /* For KVM */
    uint32_t cpuid_kvm_features;
    uint32_t cpuid_svm_features;
    int tsc_khz;

    int nr_cores;   /* number of cores within this CPU package */
    int nr_threads; /* number of threads within this CPU */
} cpuid_t;

void cpu_x86_cpuid(cpuid_t *cpuid, uint32_t index, uint32_t count, uint32_t *eax, uint32_t *ebx, uint32_t *ecx,
                   uint32_t *edx);

void x86_cpudef_setup(void);

void cpu_clear_apic_feature(cpuid_t *cpuid);

int cpu_x86_register(cpuid_t *cpuid, const char *cpu_model, int is64);

void x86_cpu_list(FILE *f, fprintf_function cpu_fprintf, const char *optarg);

/* cpuid_features bits */
#define CPUID_FP87 (1 << 0)
#define CPUID_VME (1 << 1)
#define CPUID_DE (1 << 2)
#define CPUID_PSE (1 << 3)
#define CPUID_TSC (1 << 4)
#define CPUID_MSR (1 << 5)
#define CPUID_PAE (1 << 6)
#define CPUID_MCE (1 << 7)
#define CPUID_CX8 (1 << 8)
#define CPUID_APIC (1 << 9)
#define CPUID_SEP (1 << 11) /* sysenter/sysexit */
#define CPUID_MTRR (1 << 12)
#define CPUID_PGE (1 << 13)
#define CPUID_MCA (1 << 14)
#define CPUID_CMOV (1 << 15)
#define CPUID_PAT (1 << 16)
#define CPUID_PSE36 (1 << 17)
#define CPUID_PN (1 << 18)
#define CPUID_CLFLUSH (1 << 19)
#define CPUID_DTS (1 << 21)
#define CPUID_ACPI (1 << 22)
#define CPUID_MMX (1 << 23)
#define CPUID_FXSR (1 << 24)
#define CPUID_SSE (1 << 25)
#define CPUID_SSE2 (1 << 26)
#define CPUID_SS (1 << 27)
#define CPUID_HT (1 << 28)
#define CPUID_TM (1 << 29)
#define CPUID_IA64 (1 << 30)
#define CPUID_PBE (1 << 31)

#define CPUID_EXT_SSE3 (1 << 0)
#define CPUID_EXT_DTES64 (1 << 2)
#define CPUID_EXT_MONITOR (1 << 3)
#define CPUID_EXT_DSCPL (1 << 4)
#define CPUID_EXT_VMX (1 << 5)
#define CPUID_EXT_SMX (1 << 6)
#define CPUID_EXT_EST (1 << 7)
#define CPUID_EXT_TM2 (1 << 8)
#define CPUID_EXT_SSSE3 (1 << 9)
#define CPUID_EXT_CID (1 << 10)
#define CPUID_EXT_CX16 (1 << 13)
#define CPUID_EXT_XTPR (1 << 14)
#define CPUID_EXT_PDCM (1 << 15)
#define CPUID_EXT_S2E (1 << 16)
#define CPUID_EXT_DCA (1 << 18)
#define CPUID_EXT_SSE41 (1 << 19)
#define CPUID_EXT_SSE42 (1 << 20)
#define CPUID_EXT_X2APIC (1 << 21)
#define CPUID_EXT_MOVBE (1 << 22)
#define CPUID_EXT_POPCNT (1 << 23)
#define CPUID_EXT_XSAVE (1 << 26)
#define CPUID_EXT_OSXSAVE (1 << 27)
#define CPUID_EXT_HYPERVISOR (1 << 31)

#define CPUID_EXT2_SYSCALL (1 << 11)
#define CPUID_EXT2_MP (1 << 19)
#define CPUID_EXT2_NX (1 << 20)
#define CPUID_EXT2_MMXEXT (1 << 22)
#define CPUID_EXT2_FFXSR (1 << 25)
#define CPUID_EXT2_PDPE1GB (1 << 26)
#define CPUID_EXT2_RDTSCP (1 << 27)
#define CPUID_EXT2_LM (1 << 29)
#define CPUID_EXT2_3DNOWEXT (1 << 30)
#define CPUID_EXT2_3DNOW (1 << 31)

#define CPUID_EXT3_LAHF_LM (1 << 0)
#define CPUID_EXT3_CMP_LEG (1 << 1)
#define CPUID_EXT3_SVM (1 << 2)
#define CPUID_EXT3_EXTAPIC (1 << 3)
#define CPUID_EXT3_CR8LEG (1 << 4)
#define CPUID_EXT3_ABM (1 << 5)
#define CPUID_EXT3_SSE4A (1 << 6)
#define CPUID_EXT3_MISALIGNSSE (1 << 7)
#define CPUID_EXT3_3DNOWPREFETCH (1 << 8)
#define CPUID_EXT3_OSVW (1 << 9)
#define CPUID_EXT3_IBS (1 << 10)
#define CPUID_EXT3_SKINIT (1 << 12)

#define CPUID_SVM_NPT (1 << 0)
#define CPUID_SVM_LBRV (1 << 1)
#define CPUID_SVM_SVMLOCK (1 << 2)
#define CPUID_SVM_NRIPSAVE (1 << 3)
#define CPUID_SVM_TSCSCALE (1 << 4)
#define CPUID_SVM_VMCBCLEAN (1 << 5)
#define CPUID_SVM_FLUSHASID (1 << 6)
#define CPUID_SVM_DECODEASSIST (1 << 7)
#define CPUID_SVM_PAUSEFILTER (1 << 10)
#define CPUID_SVM_PFTHRESHOLD (1 << 12)

#define CPUID_VENDOR_INTEL_1 0x756e6547 /* "Genu" */
#define CPUID_VENDOR_INTEL_2 0x49656e69 /* "ineI" */
#define CPUID_VENDOR_INTEL_3 0x6c65746e /* "ntel" */

#define CPUID_VENDOR_AMD_1 0x68747541 /* "Auth" */
#define CPUID_VENDOR_AMD_2 0x69746e65 /* "enti" */
#define CPUID_VENDOR_AMD_3 0x444d4163 /* "cAMD" */

#define CPUID_VENDOR_VIA_1 0x746e6543 /* "Cent" */
#define CPUID_VENDOR_VIA_2 0x48727561 /* "aurH" */
#define CPUID_VENDOR_VIA_3 0x736c7561 /* "auls" */

#define CPUID_MWAIT_IBE (1 << 1) /* Interrupts can exit capability */
#define CPUID_MWAIT_EMX (1 << 0) /* enumeration supported */

#ifdef __cplusplus
}
#endif

#endif
