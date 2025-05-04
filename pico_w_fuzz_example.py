#!/usr/bin/env python3
import os
import sys
import logging
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm_const import *
import unicornafl
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section

# Configuration
BINARY_PATH = "example.elf"
STACK_ADDR = 0x40000000
STACK_SIZE = 0x10000
INPUT_ADDR = 0x21000000
INPUT_SIZE = 0x1000
PAGE_SIZE = 0x1000

# Global placeholder for the target function and return addresses
target_func_addr = None
return_addr = None


def setup_logging():
    level = logging.DEBUG if os.getenv("AFL_DEBUG", "0") == "1" else logging.INFO
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=level)


def debug(msg, *args):
    logging.debug(msg, *args)


def get_function_address(elf_path, func_name):
    with open(elf_path, 'rb') as f:
        elffile = ELFFile(f)
        symtab = elffile.get_section_by_name('.symtab')
        if not symtab:
            raise RuntimeError(f"Symbol table not found in {elf_path}")
        symbols = symtab.get_symbol_by_name(func_name)
        if not symbols:
            raise RuntimeError(f"Function '{func_name}' not found in {elf_path}")
        return symbols[0]['st_value']


def find_bx_lr_address(elf_path, func_addr):
    """
    Find the first 'bx lr' (Thumb opcode 0x4770) after func_addr in the .text section.
    Returns the virtual address of the instruction.
    """
    with open(elf_path, 'rb') as f:
        elffile = ELFFile(f)
        text_sec = elffile.get_section_by_name('.text')
        if not isinstance(text_sec, Section):
            raise RuntimeError(".text section not found in ELF")
        base = text_sec['sh_addr']
        data = text_sec.data()
        start_offset = func_addr - base
        pattern = b'\x70\x47'  # little-endian 'bx lr'
        idx = data.find(pattern, start_offset)
        if idx < 0:
            raise RuntimeError(f"'bx lr' not found after 0x{func_addr:08x}")
        return base + idx


def load_elf_segments(uc, elf_path):
    with open(elf_path, 'rb') as f:
        elffile = ELFFile(f)
        for seg in elffile.iter_segments():
            if seg['p_type'] != 'PT_LOAD':
                continue

            vaddr = seg['p_vaddr']
            memsz = seg['p_memsz']
            filesz = seg['p_filesz']
            offset = seg['p_offset']

            aligned_vaddr = vaddr & ~(PAGE_SIZE - 1)
            offset_in_page = vaddr - aligned_vaddr
            aligned_size = ((offset_in_page + memsz + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE

            perms = 0
            if seg['p_flags'] & 1:
                perms |= UC_PROT_EXEC
            if seg['p_flags'] & 2:
                perms |= UC_PROT_WRITE
            if seg['p_flags'] & 4:
                perms |= UC_PROT_READ

            try:
                uc.mem_map(aligned_vaddr, aligned_size, perms)
                debug("Mapped segment: addr=0x%08x size=0x%x perms=%d", aligned_vaddr, aligned_size, perms)
                f.seek(offset)
                uc.mem_write(vaddr, f.read(filesz))
            except Exception as e:
                debug("Failed mapping at 0x%08x: %s", aligned_vaddr, e)


def place_input(uc, input_data, _index, _data):
    debug("Injecting input (%d bytes)", len(input_data))
    uc.mem_write(INPUT_ADDR, input_data)
    uc.reg_write(UC_ARM_REG_R0, INPUT_ADDR)
    uc.reg_write(UC_ARM_REG_R1, len(input_data))
    uc.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE - 0x10)
    uc.reg_write(UC_ARM_REG_PC, target_func_addr | 1)
    return True


def hook_code(uc, address, size, user_data):
    debug("Executing @ 0x%08x (size=%d)", address, size)
    return True


def main():
    setup_logging()

    if len(sys.argv) != 2:
        logging.error("Usage: %s <afl_input_file>", sys.argv[0])
        sys.exit(1)

    afl_input = sys.argv[1]
    global target_func_addr, return_addr

    target_func_addr = get_function_address(BINARY_PATH, 'process_payload')
    logging.info("Function 'process_payload' @ 0x%08x", target_func_addr)

    # Determine return address
    try:
        return_addr = find_bx_lr_address(BINARY_PATH, target_func_addr)
        logging.info("Identified return 'bx lr' @ 0x%08x", return_addr)
    except Exception as e:
        logging.error("Exception finding exit: %s", e)
        sys.exit(1)

    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.hook_add(UC_HOOK_CODE, hook_code)

    load_elf_segments(uc, BINARY_PATH)
    uc.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(INPUT_ADDR, INPUT_SIZE, UC_PROT_READ | UC_PROT_WRITE)

    exits = [return_addr]

    logging.info("Starting AFL loop starting @ 0x%08x with exit @ 0x%08x", target_func_addr, return_addr)
    unicornafl.uc_afl_fuzz(
        uc,
        afl_input,
        place_input,
        exits
    )


if __name__ == '__main__':
    main()
