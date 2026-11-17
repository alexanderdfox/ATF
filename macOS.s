// mesh_macos.s  -  Fork-bomb guard for macOS Apple Silicon (M1+)
//
// Build (recommended):
//   clang -o mesh mesh_macos.s
//
// or manually:
//   as -arch arm64 -o mesh.o mesh_macos.s
//   ld -arch arm64 -o mesh mesh.o -lSystem -syslibroot $(xcrun --show-sdk-path)
//
// Run:
//   sudo ./mesh

.equ PROC_ALL_PIDS,  1
.equ FORK_THRESHOLD, 800
.equ MAX_PROCS,      1024
.equ NAME_LEN,       64
.equ PROC_SIZE,      68          // 4-byte pid + 64-byte name

.section __TEXT,__text
.global _main
.align 2

// External symbols from libSystem / libproc
.extern _proc_listpids
.extern _proc_name
.extern _getpid
.extern _kill
.extern _nanosleep
.extern _write

_main:
    // Print banner
    adrp    x0, msg_banner@PAGE
    add     x0, x0, msg_banner@PAGEOFF
    bl      print_cstr

    adrp    x0, msg_banner2@PAGE
    add     x0, x0, msg_banner2@PAGEOFF
    bl      print_cstr

    adrp    x0, msg_banner3@PAGE
    add     x0, x0, msg_banner3@PAGEOFF
    bl      print_cstr

    // my_pid = getpid()
    bl      _getpid
    adrp    x1, my_pid@PAGE
    str     w0, [x1, my_pid@PAGEOFF]

    adrp    x0, msg_mypid@PAGE
    add     x0, x0, msg_mypid@PAGEOFF
    bl      print_cstr

    adrp    x1, my_pid@PAGE
    ldr     w0, [x1, my_pid@PAGEOFF]
    bl      print_uint

    adrp    x0, msg_nl@PAGE
    add     x0, x0, msg_nl@PAGEOFF
    bl      print_cstr
    bl      print_cstr          // extra blank line

main_loop:
    bl      monitor_and_mitigate

    // nanosleep({2, 0}, NULL)
    adrp    x0, ts@PAGE
    add     x0, x0, ts@PAGEOFF
    mov     x1, #2
    str     x1, [x0]            // tv_sec
    str     xzr, [x0, #8]       // tv_nsec
    mov     x1, #0              // remaining = NULL
    bl      _nanosleep

    b       main_loop

// ------------------------------------------------------------
// monitor_and_mitigate
// ------------------------------------------------------------
monitor_and_mitigate:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    stp     x19, x20, [sp, #-16]!
    stp     x21, x22, [sp, #-16]!
    stp     x23, x24, [sp, #-16]!

    // Reset process count
    adrp    x0, proc_count@PAGE
    str     wzr, [x0, proc_count@PAGEOFF]

    // First call: get required buffer size
    // proc_listpids(PROC_ALL_PIDS, 0, NULL, 0)
    mov     w0, #PROC_ALL_PIDS
    mov     w1, #0
    mov     x2, #0
    mov     w3, #0
    bl      _proc_listpids
    // x0 = bytes needed (or -1 on error)
    cmp     x0, #0
    b.le    mon_done

    // Cap at MAX_PROCS * 4
    mov     x1, #(MAX_PROCS * 4)
    cmp     x0, x1
    csel    x19, x0, x1, lt     // x19 = bytes to allocate/use

    // Second call: fill the pid buffer
    mov     w0, #PROC_ALL_PIDS
    mov     w1, #0
    adrp    x2, pid_buf@PAGE
    add     x2, x2, pid_buf@PAGEOFF
    mov     w3, w19
    bl      _proc_listpids
    cmp     x0, #0
    b.le    mon_done

    // number of pids = bytes / 4
    lsr     x20, x0, #2         // x20 = num_pids
    cmp     x20, #MAX_PROCS
    csel    x20, x20, x1, lt    // clamp

    mov     x21, #0             // i = 0

fill_procs:
    cmp     x21, x20
    b.ge    count_done

    // pid = pid_buf[i]
    adrp    x0, pid_buf@PAGE
    add     x0, x0, pid_buf@PAGEOFF
    ldr     w22, [x0, x21, lsl #2]   // w22 = pid

    cbz     w22, next_pid       // skip pid 0

    // proc_name(pid, namebuf, NAME_LEN)
    mov     w0, w22
    adrp    x1, namebuf@PAGE
    add     x1, x1, namebuf@PAGEOFF
    mov     w2, #NAME_LEN
    bl      _proc_name
    // returns length or 0 on failure – we just use the buffer

    // Store into procs[]
    adrp    x0, proc_count@PAGE
    ldr     w1, [x0, proc_count@PAGEOFF]
    cmp     w1, #MAX_PROCS
    b.ge    next_pid

    // offset = count * PROC_SIZE
    mov     w2, #PROC_SIZE
    mul     w2, w1, w2
    adrp    x3, procs@PAGE
    add     x3, x3, procs@PAGEOFF
    add     x3, x3, x2

    str     w22, [x3]           // store pid
    add     x3, x3, #4

    // copy name
    adrp    x0, namebuf@PAGE
    add     x0, x0, namebuf@PAGEOFF
    mov     x1, x3
    bl      strcpy

    // increment count
    adrp    x0, proc_count@PAGE
    ldr     w1, [x0, proc_count@PAGEOFF]
    add     w1, w1, #1
    str     w1, [x0, proc_count@PAGEOFF]

next_pid:
    add     x21, x21, #1
    b       fill_procs

count_done:
    // Print total
    adrp    x0, msg_total@PAGE
    add     x0, x0, msg_total@PAGEOFF
    bl      print_cstr

    adrp    x0, proc_count@PAGE
    ldr     w0, [x0, proc_count@PAGEOFF]
    bl      print_uint

    adrp    x0, msg_nl@PAGE
    add     x0, x0, msg_nl@PAGEOFF
    bl      print_cstr

    // Check threshold
    adrp    x0, proc_count@PAGE
    ldr     w0, [x0, proc_count@PAGEOFF]
    cmp     w0, #FORK_THRESHOLD
    b.le    secure

    // === CRITICAL PATH ===
    adrp    x0, msg_critical@PAGE
    add     x0, x0, msg_critical@PAGEOFF
    bl      print_cstr

    adrp    x0, proc_count@PAGE
    ldr     w0, [x0, proc_count@PAGEOFF]
    bl      print_uint

    adrp    x0, msg_procs@PAGE
    add     x0, x0, msg_procs@PAGEOFF
    bl      print_cstr

    // Find most common name (O(n²))
    adrp    x0, rogue_count@PAGE
    str     wzr, [x0, rogue_count@PAGEOFF]
    adrp    x0, rogue_name@PAGE
    add     x0, x0, rogue_name@PAGEOFF
    strb    wzr, [x0]

    adrp    x0, proc_count@PAGE
    ldr     w23, [x0, proc_count@PAGEOFF]   // n
    mov     w24, #0                         // i

find_i:
    cmp     w24, w23
    b.ge    found_rogue

    // name of i
    mov     w0, #PROC_SIZE
    mul     w0, w24, w0
    adrp    x1, procs@PAGE
    add     x1, x1, procs@PAGEOFF
    add     x1, x1, x0
    add     x25, x1, #4                     // x25 = name_i

    mov     w26, #0                         // current_count
    mov     w27, #0                         // j

find_j:
    cmp     w27, w23
    b.ge    check_max

    mov     w0, #PROC_SIZE
    mul     w0, w27, w0
    adrp    x1, procs@PAGE
    add     x1, x1, procs@PAGEOFF
    add     x1, x1, x0
    add     x0, x1, #4                      // name_j

    mov     x1, x25
    bl      strcmp
    cbnz    w0, next_j
    add     w26, w26, #1
next_j:
    add     w27, w27, #1
    b       find_j

check_max:
    adrp    x0, rogue_count@PAGE
    ldr     w0, [x0, rogue_count@PAGEOFF]
    cmp     w26, w0
    b.le    next_i

    // new max
    adrp    x0, rogue_count@PAGE
    str     w26, [x0, rogue_count@PAGEOFF]
    adrp    x0, rogue_name@PAGE
    add     x0, x0, rogue_name@PAGEOFF
    mov     x1, x25
    bl      strcpy

next_i:
    add     w24, w24, #1
    b       find_i

found_rogue:
    adrp    x0, rogue_count@PAGE
    ldr     w0, [x0, rogue_count@PAGEOFF]
    cmp     w0, #50
    b.lt    mon_done

    // Purge
    adrp    x0, msg_purging@PAGE
    add     x0, x0, msg_purging@PAGEOFF
    bl      print_cstr

    adrp    x0, rogue_name@PAGE
    add     x0, x0, rogue_name@PAGEOFF
    bl      print_cstr

    adrp    x0, msg_purging2@PAGE
    add     x0, x0, msg_purging2@PAGEOFF
    bl      print_cstr

    mov     w24, #0
purge_loop:
    cmp     w24, w23
    b.ge    mon_done

    mov     w0, #PROC_SIZE
    mul     w0, w24, w0
    adrp    x1, procs@PAGE
    add     x1, x1, procs@PAGEOFF
    add     x1, x1, x0
    ldr     w22, [x1]                       // pid
    add     x25, x1, #4                     // name

    // name match?
    mov     x0, x25
    adrp    x1, rogue_name@PAGE
    add     x1, x1, rogue_name@PAGEOFF
    bl      strcmp
    cbnz    w0, next_purge

    // pid > 1 && pid != my_pid
    cmp     w22, #1
    b.le    next_purge
    adrp    x0, my_pid@PAGE
    ldr     w0, [x0, my_pid@PAGEOFF]
    cmp     w22, w0
    b.eq    next_purge

    // print + kill
    adrp    x0, msg_term@PAGE
    add     x0, x0, msg_term@PAGEOFF
    bl      print_cstr
    mov     w0, w22
    bl      print_uint
    adrp    x0, msg_nl@PAGE
    add     x0, x0, msg_nl@PAGEOFF
    bl      print_cstr

    mov     w0, w22
    mov     w1, #9                          // SIGKILL
    bl      _kill

next_purge:
    add     w24, w24, #1
    b       purge_loop

secure:
    adrp    x0, msg_secure@PAGE
    add     x0, x0, msg_secure@PAGEOFF
    bl      print_cstr

mon_done:
    adrp    x0, msg_sep@PAGE
    add     x0, x0, msg_sep@PAGEOFF
    bl      print_cstr

    ldp     x23, x24, [sp], #16
    ldp     x21, x22, [sp], #16
    ldp     x19, x20, [sp], #16
    ldp     x29, x30, [sp], #16
    ret

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

// print_cstr(x0 = C string)
print_cstr:
    mov     x19, x0
    mov     x2, #0
1:  ldrb    w3, [x19, x2]
    cbz     w3, 2f
    add     x2, x2, #1
    b       1b
2:  mov     x0, #1              // stdout
    mov     x1, x19
    // x2 = length
    bl      _write
    ret

// print_uint(w0 = number)
print_uint:
    stp     x29, x30, [sp, #-16]!
    adrp    x1, numbuf@PAGE
    add     x1, x1, numbuf@PAGEOFF
    add     x1, x1, #15
    strb    wzr, [x1]
    mov     w2, #10
1:  udiv    w3, w0, w2
    msub    w4, w3, w2, w0
    add     w4, w4, #'0'
    sub     x1, x1, #1
    strb    w4, [x1]
    mov     w0, w3
    cbnz    w0, 1b
    mov     x0, x1
    bl      print_cstr
    ldp     x29, x30, [sp], #16
    ret

// strcpy(x0 = src, x1 = dest)  – note argument order for convenience
strcpy:
1:  ldrb    w2, [x0], #1
    strb    w2, [x1], #1
    cbnz    w2, 1b
    ret

// strcmp(x0, x1) → w0 == 0 if equal
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

// ------------------------------------------------------------
// Data
// ------------------------------------------------------------
.section __DATA,__data
.align 3

msg_banner:     .asciz "==================================================\n"
msg_banner2:    .asciz "   macOS Apple Silicon Telemetry & Fork-Bomb Guard\n"
msg_banner3:    .asciz "==================================================\n"
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

.section __DATA,__bss
.align 3
my_pid:         .space 4
proc_count:     .space 4
rogue_count:    .space 4
rogue_name:     .space NAME_LEN
namebuf:        .space NAME_LEN
numbuf:         .space 16
ts:             .space 16
pid_buf:        .space MAX_PROCS * 4
procs:          .space MAX_PROCS * PROC_SIZE
