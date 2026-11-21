import ida_bytes
import ida_kernwin
import ida_idaapi
import os

START = 0xFC100000
SIZE  = 0x10000

def dump_region(start, size):
    if size <= 0:
        raise ValueError("Invalid size")

    filename = ida_kernwin.ask_file(
        True,
        "*.bin",
        "Save memory dump"
    )

    if not filename:
        print("[-] Cancelled")
        return

    data = ida_bytes.get_bytes(start, size)

    if data is None or len(data) != size:
        raise RuntimeError(
            f"Read failed: VA={start:#x}, SIZE={size:#x}"
        )

    with open(filename, "wb") as f:
        f.write(data)

    print(f"[+] Dumped: {filename}")
    print(f"[+] Start: {start:#010x}")
    print(f"[+] Size:  {size:#x} ({size} bytes)")

dump_region(START, SIZE)
