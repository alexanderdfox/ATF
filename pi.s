// mesh.s  -  Cross-platform fork-bomb guard (AArch64 / Raspberry Pi 64-bit)
// Assemble + link on Raspberry Pi:
//   as -o mesh.o mesh.s
//   ld -o mesh mesh.o
//   ./mesh
//
// Syscall numbers (AArch64 Linux):
//   openat=56, close=57, getdents64=61, read=63, write=64,
//   getpid=172, kill=129, nanosleep=101

.equ AT_FDCWD,       -100
.equ O_RDONLY,       0
.equ O_DIRECTORY,    0200000
.equ SYS_openat,     56
.equ SYS_close,      57
.equ SYS_getdents64, 61
.equ SYS_read,       63
.equ SYS_write,      64
.equ SYS_getpid,     172
.equ SYS_kill,       129
.equ SYS_nanosleep,  101
.equ SIGKILL,        9

.equ FORK_THRESHOLD, 800
.equ MAX_PROCS,      1024          // reduced from 4096 for practical BSS size
.equ NAME_LEN,       64            // enough for most process names
.equ PROC_SIZE,      68            // 4 (pid) + 64 (name)

.section .data
msg_banner:     .asciz "==================================================\n"
                .asciz "   AArch64 Telemetry & Fork-Bomb Guard (RPi)\n"
                .asciz "==================================================\n"
msg_mypid:      .asciz "My PID: "
msg_total:      .asciz "[Telemetry] Total Active Processes: "
msg_critical:   .asciz "\n[!] CRITICAL: FORK BOMB DETECTED ("
msg_procs:      .asciz " processes)!\n"
msg_purging:    .asciz "[!] Purging instances of runaway process '"
msg_purging2:   .asciz "'...\n"
msg_term:       .asciz " -> Terminating PID "
msg_secure:     .asciz "[Status] Secure: Fork Bomb Guard Active (Zero threats detected)\n"
msg_sep:        .asciz "--------------------------------------------------\n"
msg_nl:         .asciz "\n"
path_proc:      .asciz "/proc"
path_comm:      .asciz "/comm"
digits:         .asciz "0123456789"

.section .bss
.align 8
my_pid:         .skip 4
proc_count:     .skip 4
rogue_count:    .skip 4
rogue_name:     .skip NAME_LEN
dirbuf:         .skip 16384         // getdents buffer
pathbuf:        .skip 128           // /proc/<pid>/comm
namebuf:        .skip NAME_LEN
numbuf:         .skip 16
procs:          .skip MAX_PROCS * PROC_SIZE
ts:             .skip 16            // timespec for nanosleep

.section .text
.global _start

_start:
    // Print banner
    adr     x0, msg_banner
    bl      print_cstr
    adr     x0, msg_banner + 51
    bl      print_cstr
    adr     x0, msg_banner + 102
    bl      print_cstr

    // getpid
    mov     x8, SYS_getpid
    svc     #0
    str     w0, [my_pid]

    adr     x0, msg_mypid
    bl      print_cstr
    ldr     w0, [my_pid]
    bl      print_uint
    adr     x0, msg_nl
    bl      print_cstr
    adr     x0, msg_nl
    bl      print_cstr

main_loop:
    bl      monitor_and_mitigate

    // sleep(2)
    adr     x0, ts
    mov     x1, #2
    str     x1, [x0]            // tv_sec = 2
    str     xzr, [x0, #8]       // tv_nsec = 0
    mov     x1, #0              // remaining = NULL
    mov     x8, SYS_nanosleep
    svc     #0

    b       main_loop

// ------------------------------------------------------------
// monitor_and_mitigate
// ------------------------------------------------------------
monitor_and_mitigate:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp

    // Reset count
    str     wzr, [proc_count]

    // openat(AT_FDCWD, "/proc", O_RDONLY|O_DIRECTORY)
    mov     x0, AT_FDCWD
    adr     x1, path_proc
    mov     x2, #(O_RDONLY | O_DIRECTORY)
    mov     x3, #0
    mov     x8, SYS_openat
    svc     #0
    cmp     x0, #0
    b.lt    mon_done
    mov     w19, w0             // save /proc fd

read_dents:
    // getdents64(fd, dirbuf, 16384)
    mov     w0, w19
    adr     x1, dirbuf
    mov     x2, #16384
    mov     x8, SYS_getdents64
    svc     #0
    cmp     x0, #0
    b.le    close_proc          // 0 = end, <0 = error
    mov     x20, x0             // bytes read
    adr     x21, dirbuf         // current pointer

dents_loop:
    cbz     x20, read_dents     // need more?
    // linux_dirent64: d_ino(8) d_off(8) d_reclen(2) d_type(1) d_name[]
    ldrh    w22, [x21, #16]     // d_reclen
    add     x23, x21, #19       // d_name

    // Check if name is purely numeric (PID)
    mov     x0, x23
    bl      is_all_digits
    cbz     w0, next_dent

    // Convert name to int
    mov     x0, x23
    bl      atoi
    mov     w24, w0             // pid

    // Skip pid 0
    cbz     w24, next_dent

    // Build path /proc/<pid>/comm
    adr     x0, pathbuf
    adr     x1, path_proc
    bl      strcpy
    mov     x0, x0              // end of "/proc"
    mov     w1, #'/'
    strb    w1, [x0], #1
    mov     x1, x23             // pid string
    bl      strcpy
    mov     x0, x0
    adr     x1, path_comm
    bl      strcpy

    // openat the comm file
    mov     x0, AT_FDCWD
    adr     x1, pathbuf
    mov     x2, #O_RDONLY
    mov     x3, #0
    mov     x8, SYS_openat
    svc     #0
    cmp     x0, #0
    b.lt    next_dent
    mov     w25, w0             // comm fd

    // read name
    mov     w0, w25
    adr     x1, namebuf
    mov     x2, #NAME_LEN-1
    mov     x8, SYS_read
    svc     #0
    cmp     x0, #0
    b.le    close_comm
    // strip trailing newline
    adr     x1, namebuf
    add     x1, x1, x0
    sub     x1, x1, #1
    ldrb    w2, [x1]
    cmp     w2, #'\n'
    b.ne    1f
    strb    wzr, [x1]
1:
    // close comm
    mov     w0, w25
    mov     x8, SYS_close
    svc     #0

    // Store in procs[] if room
    ldr     w0, [proc_count]
    cmp     w0, #MAX_PROCS
    b.ge    next_dent

    // index = count * PROC_SIZE
    mov     w1, #PROC_SIZE
    mul     w1, w0, w1
    adr     x2, procs
    add     x2, x2, x1
    str     w24, [x2]           // pid
    add     x2, x2, #4
    adr     x1, namebuf
    mov     x0, x2
    bl      strcpy

    // increment count
    add     w0, w0, #1
    str     w0, [proc_count]

next_dent:
    add     x21, x21, x22       // next entry
    sub     x20, x20, x22
    b       dents_loop

close_comm:
    mov     w0, w25
    mov     x8, SYS_close
    svc     #0
    b       next_dent

close_proc:
    mov     w0, w19
    mov     x8, SYS_close
    svc     #0

    // Print total
    adr     x0, msg_total
    bl      print_cstr
    ldr     w0, [proc_count]
    bl      print_uint
    adr     x0, msg_nl
    bl      print_cstr

    // Check threshold
    ldr     w0, [proc_count]
    cmp     w0, #FORK_THRESHOLD
    b.le    secure

    // Critical
    adr     x0, msg_critical
    bl      print_cstr
    ldr     w0, [proc_count]
    bl      print_uint
    adr     x0, msg_procs
    bl      print_cstr

    // Find most common name (O(n²))
    str     wzr, [rogue_count]
    adr     x0, rogue_name
    strb    wzr, [x0]

    ldr     w26, [proc_count]   // n
    mov     w27, #0             // i

find_i:
    cmp     w27, w26
    b.ge    found_rogue

    // get name of i
    mov     w0, #PROC_SIZE
    mul     w0, w27, w0
    adr     x1, procs
    add     x1, x1, x0
    add     x28, x1, #4         // name_i

    mov     w29, #0             // current_count
    mov     w30, #0             // j

find_j:
    cmp     w30, w26
    b.ge    check_max

    mov     w0, #PROC_SIZE
    mul     w0, w30, w0
    adr     x1, procs
    add     x1, x1, x0
    add     x0, x1, #4          // name_j
    mov     x1, x28
    bl      strcmp
    cbnz    w0, next_j
    add     w29, w29, #1
next_j:
    add     w30, w30, #1
    b       find_j

check_max:
    ldr     w0, [rogue_count]
    cmp     w29, w0
    b.le    next_i
    str     w29, [rogue_count]
    adr     x0, rogue_name
    mov     x1, x28
    bl      strcpy
next_i:
    add     w27, w27, #1
    b       find_i

found_rogue:
    ldr     w0, [rogue_count]
    cmp     w0, #50
    b.lt    mon_done

    // Purge
    adr     x0, msg_purging
    bl      print_cstr
    adr     x0, rogue_name
    bl      print_cstr
    adr     x0, msg_purging2
    bl      print_cstr

    mov     w27, #0
purge_loop:
    cmp     w27, w26
    b.ge    mon_done

    mov     w0, #PROC_SIZE
    mul     w0, w27, w0
    adr     x1, procs
    add     x1, x1, x0
    ldr     w24, [x1]           // pid
    add     x28, x1, #4         // name

    // name match?
    mov     x0, x28
    adr     x1, rogue_name
    bl      strcmp
    cbnz    w0, next_purge

    // pid > 1 && pid != my_pid
    cmp     w24, #1
    b.le    next_purge
    ldr     w0, [my_pid]
    cmp     w24, w0
    b.eq    next_purge

    // print + kill
    adr     x0, msg_term
    bl      print_cstr
    mov     w0, w24
    bl      print_uint
    adr     x0, msg_nl
    bl      print_cstr

    mov     w0, w24
    mov     w1, #SIGKILL
    mov     x8, SYS_kill
    svc     #0

next_purge:
    add     w27, w27, #1
    b       purge_loop

secure:
    adr     x0, msg_secure
    bl      print_cstr

mon_done:
    adr     x0, msg_sep
    bl      print_cstr

    ldp     x29, x30, [sp], #16
    ret

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

// print_cstr(x0 = nul-terminated string)
print_cstr:
    mov     x1, x0
    mov     x2, #0
1:  ldrb    w3, [x1, x2]
    cbz     w3, 2f
    add     x2, x2, #1
    b       1b
2:  mov     x0, #1              // stdout
    // x1 already points to string
    mov     x8, SYS_write
    svc     #0
    ret

// print_uint(w0 = number)
print_uint:
    stp     x29, x30, [sp, #-16]!
    adr     x1, numbuf + 15
    strb    wzr, [x1]
    mov     w2, #10
1:  udiv    w3, w0, w2
    msub    w4, w3, w2, w0      // rem
    add     w4, w4, #'0'
    sub     x1, x1, #1
    strb    w4, [x1]
    mov     w0, w3
    cbnz    w0, 1b
    mov     x0, x1
    bl      print_cstr
    ldp     x29, x30, [sp], #16
    ret

// is_all_digits(x0 = string) -> w0 = 1 if yes
is_all_digits:
    mov     w1, #1
1:  ldrb    w2, [x0], #1
    cbz     w2, 2f
    cmp     w2, #'0'
    b.lt    3f
    cmp     w2, #'9'
    b.gt    3f
    b       1b
3:  mov     w1, #0
2:  mov     w0, w1
    ret

// atoi(x0 = string) -> w0
atoi:
    mov     w1, #0
1:  ldrb    w2, [x0], #1
    cbz     w2, 2f
    sub     w2, w2, #'0'
    mov     w3, #10
    madd    w1, w1, w3, w2
    b       1b
2:  mov     w0, w1
    ret

// strcpy(x0 = dest, x1 = src) -> x0 = end of dest (after nul)
strcpy:
1:  ldrb    w2, [x1], #1
    strb    w2, [x0], #1
    cbnz    w2, 1b
    sub     x0, x0, #1          // point at the nul
    ret

// strcmp(x0, x1) -> w0 = 0 if equal
strcmp:
1:  ldrb    w2, [x0], #1
    ldrb    w3, [x1], #1
    cmp     w2, w3
    b.ne    2f
    cbnz    w2, 1b
    mov     w0, #0
    ret
2:  mov     w0, #1
    ret
