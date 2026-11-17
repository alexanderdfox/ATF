# ATF — Anti-Threat Forkbomb / Telemetry Guard

**Reboot**

Pure AArch64 assembly process telemetry and fork-bomb mitigation for:

- **macOS Apple Silicon** (`macOS.s`)
- **Linux AArch64 / Raspberry Pi** (`pi.s`)

## What it does

Continuously monitors the process list. When the total number of processes exceeds a threshold (default **800**), it identifies the most common process name and SIGKILLs excess instances of it (skipping PID 1 and its own PID). It prints telemetry on every cycle.

## Files

| File       | Target                     | Notes                                      |
|------------|----------------------------|--------------------------------------------|
| `macOS.s`  | macOS Apple Silicon (M1+)  | Uses `libproc` (`proc_listpids`, `proc_name`) |
| `pi.s`     | Linux AArch64 (RPi, etc.)  | Pure syscalls via `/proc`                  |
| `LICENSE`  | MIT                        |                                            |

## Build & Run

### macOS (Apple Silicon)

```bash
clang -o mesh macOS.s
# or
as -arch arm64 -o mesh.o macOS.s
ld -arch arm64 -o mesh mesh.o -lSystem -syslibroot $(xcrun --show-sdk-path)

sudo ./mesh
```

### Raspberry Pi / Linux AArch64

```bash
as -o mesh.o pi.s
ld -o mesh mesh.o
./mesh          # root recommended for reliable kill
```

## Behavior

- Sleeps 2 seconds between scans
- Threshold: 800 processes
- Only purges a process name that appears ≥ 50 times
- Never kills PID 1 or itself
- Prints clear status / critical / purge messages

## Notes

- Extremely lightweight (no libc dependency on the Linux version)
- Intended as a last-line defense / educational example of low-level process monitoring
- Requires elevated privileges for reliable process termination

## License

MIT License · Copyright (c) 2026 Alex Fox
