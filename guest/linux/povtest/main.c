/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2024 Vitaly Chipounov
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libpov.h>

// TODO: randomize these values.
static type_request s_pov_req;
static type1_vals s_t1 = {.ipval = 0xdeadbed, .regval = 0xbadf00d};

static const char *s_t2_flag = "cgc{flag}";
#define s_t2_size 0x10
static uint8_t s_t2_buffer[s_t2_size];
static type2_vals s_t2 = {.read_size = s_t2_size, .region_addr = 0x4347c000, .region_size = 0x1000};

static int s_has_segfault;
static uintptr_t s_segfault_addr;
struct user_regs_struct s_segfault_regs;

static uint32_t get_reg(const struct user_regs_struct *regs, int regnum) {
    switch (regnum) {
        case 0:
            return regs->eax;
        case 1:
            return regs->ecx;
        case 2:
            return regs->edx;
        case 3:
            return regs->ebx;
        case 4:
            return regs->esp;
        case 5:
            return regs->ebp;
        case 6:
            return regs->esi;
        case 7:
            return regs->edi;
        default:
            fprintf(stderr, "Invalid reg %d\n", regnum);
    }

    return 0;
}

static int validate_type1() {
    if (!s_has_segfault) {
        fprintf(stderr, "Binary has not crashed\n");
        return -1;
    }

    uint32_t expected_eip = s_t1.ipval & s_pov_req.type1.ipmask;
    uint32_t actual_eip = s_segfault_regs.eip & s_pov_req.type1.ipmask;
    if (expected_eip != actual_eip) {
        fprintf(stderr, "Unexpected IP at crash: expected=%#x actual=%#x\n", expected_eip, actual_eip);
        return -1;
    }

    uint32_t actual_reg = get_reg(&s_segfault_regs, s_pov_req.type1.regnum);
    actual_reg = actual_reg & s_pov_req.type1.regmask;
    uint32_t expected_reg = s_t1.regval & s_pov_req.type1.regmask;
    if (actual_reg != expected_reg) {
        fprintf(stderr, "Unexpected reg value at crash: expected=%#x actual=%#x\n", expected_reg, actual_reg);
        return -1;
    }

    return 0;
}

static int validate_type2() {
    if (strcmp((const char *) s_t2_buffer, s_t2_flag) == 0) {
        return 0;
    }

    fprintf(stderr, "Unexpected buffer content\n");
    return -1;
}

static int validate_pov() {
    switch (s_pov_req.povType) {
        case 1: {
            return validate_type1();
        } break;

        case 2: {
            return validate_type2();
        } break;
        default:
            fprintf(stderr, "POV not negotiated\n");
            return -1;
    }

    return 0;
}

static void *negotiation_thread(void *pipeptr) {
    int fd = *(int *) pipeptr;

    printf("Starting negotation thread fd=%d\n", fd);

    int ret = type_negotiate(fd, &s_pov_req);
    if (ret < 0) {
        fprintf(stderr, "Could not negotiate POV\n");
        return NULL;
    }

    if (s_pov_req.povType == 1) {
        printf("Negotiating type 1 pov\n");
        int ret = write(fd, &s_t1, sizeof(s_t1));
        if (ret != sizeof(s_t1)) {
            fprintf(stderr, "Could not write negotiated values to POV\n");
            return NULL;
        }
    } else if (s_pov_req.povType == 2) {
        printf("Negotiating type 2 pov\n");

        int ret = write(fd, &s_t2, sizeof(s_t2));
        if (ret != sizeof(s_t2)) {
            fprintf(stderr, "Could not write negotiated values to POV\n");
            return NULL;
        }

        ret = read(fd, s_t2_buffer, s_t2_size);
        if (ret != s_t2_size) {
            fprintf(stderr, "Could not read type2 pov data");
            return NULL;
        }
    } else {
        fprintf(stderr, "Invalid pov type %d\n", s_pov_req.povType);
    }

    return NULL;
}

void print_registers(struct user_regs_struct *regs) {
    printf("Registers:\n");
    printf("EBX: %lx\n", regs->ebx);
    printf("ECX: %lx\n", regs->ecx);
    printf("EDX: %lx\n", regs->edx);
    printf("ESI: %lx\n", regs->esi);
    printf("EDI: %lx\n", regs->edi);
    printf("EBP: %lx\n", regs->ebp);
    printf("EAX: %lx\n", regs->eax);
    printf("ORIG_EAX: %lx\n", regs->orig_eax);
    printf("EIP: %lx\n", regs->eip);
    printf("ESP: %lx\n", regs->esp);
}

static int intercept_segfault_in_cb(int pid) {
    int status;
    while (1) {
        siginfo_t info = {0};

        if (waitpid(pid, &status, 0) < 0) {
            // This happens when the process is terminated.
            return 0;
        }

        if (WIFEXITED(status)) {
            // Child process exited normally
            break;
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            switch (sig) {
                case SIGTRAP:
                    // Do not pass this signal to the child.
                    sig = 0;
                    break;

                case SIGBUS:
                case SIGSEGV: {
                    s_has_segfault = 1;

                    if (ptrace(PTRACE_GETREGS, pid, NULL, &s_segfault_regs) == -1) {
                        fprintf(stderr, "PTRACE_GETREGS failed");
                        return -1;
                    }

                    if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &info) == -1) {
                        fprintf(stderr, "PTRACE_GETSIGINFO failed");
                        return -1;
                    }

                    printf("SEGFAULT at %p\n", info.si_addr);
                    s_segfault_addr = (uintptr_t) info.si_addr;

                    print_registers(&s_segfault_regs);
                } break;

                default:
                    break;
            }

            if (ptrace(PTRACE_CONT, pid, NULL, sig) == -1) {
                fprintf(stderr, "PTRACE_CONT failed");
                return -1;
            }
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s --pov=/path/to/pov/binary -- /path/to/cgcload /path/to/challenge/binary\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *pov_path = NULL;
    char **cgcload_args = NULL;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--pov=", 6) == 0) {
            pov_path = argv[i] + 6;
        } else if (strcmp(argv[i], "--") == 0) {
            cgcload_args = &argv[i + 1];
            break;
        }
    }

    if (pov_path == NULL || cgcload_args == NULL || cgcload_args[0] == NULL) {
        fprintf(stderr, "Invalid arguments\n");
        exit(EXIT_FAILURE);
    }

    if (access(pov_path, F_OK) != 0) {
        fprintf(stderr, "%s does not exist\n", pov_path);
        exit(EXIT_FAILURE);
    }

    if (access(cgcload_args[0], F_OK) != 0) {
        fprintf(stderr, "%s does not exist\n", cgcload_args[0]);
        exit(EXIT_FAILURE);
    }

    int pipe1[2];
    int pipe2[2];
    int pipeneg[2];

    if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pipeneg) < 0) {
        fprintf(stderr, "Could not create pov negotation socket\n");
        exit(EXIT_FAILURE);
    }

    if (pipe(pipe1) == -1 || pipe(pipe2) == -1) {
        fprintf(stderr, "Could not create pipes\n");
        exit(EXIT_FAILURE);
    }

    pthread_t tid;
    if (pthread_create(&tid, NULL, negotiation_thread, &pipeneg[0]) < 0) {
        fprintf(stderr, "Could not create thread\n");
        exit(EXIT_FAILURE);
    }

    pid_t pov_pid = fork();
    if (pov_pid == -1) {
        exit(EXIT_FAILURE);
    }

    if (pov_pid == 0) {
        close(pipe2[1]); // Close write end of pipe1
        close(pipe1[0]); // Close read end of pipe2

        dup2(pipe2[0], STDIN_FILENO);
        dup2(pipe1[1], STDOUT_FILENO);

        dup2(pipeneg[1], NEG_FD);

        execl(pov_path, pov_path, NULL);
        exit(EXIT_FAILURE);
    }

    pid_t cgcload_pid = fork();
    if (cgcload_pid == -1) {
        exit(EXIT_FAILURE);
    }

    if (cgcload_pid == 0) {
        // Allow parent to trace this process
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            fprintf(stderr, "Could not init ptrace inside cgcload\n");
            exit(EXIT_FAILURE);
        }

        close(pipe1[1]); // Close write end of pipe1
        close(pipe2[0]); // Close read end of pipe2

        dup2(pipe1[0], STDIN_FILENO);
        dup2(pipe2[1], STDOUT_FILENO);

        execv(cgcload_args[0], cgcload_args);
        exit(EXIT_FAILURE);
    }

    if (intercept_segfault_in_cb(cgcload_pid) < 0) {
        fprintf(stderr, "Failed to intercept segfault in CB\n");
        exit(EXIT_FAILURE);
    }

    if (waitpid(pov_pid, NULL, 0) == -1) {
        fprintf(stderr, "Failed waiting for pov binary\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_join(tid, NULL) < 0) {
        fprintf(stderr, "Could not join negotiation thread\n");
        exit(EXIT_FAILURE);
    }

    if (validate_pov() < 0) {
        fprintf(stderr, "Could not validate pov\n");
        exit(EXIT_FAILURE);
    }

    printf("POV SUCCESS\n");

    return 0;
}
