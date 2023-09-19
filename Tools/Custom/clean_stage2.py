import os
import re
import struct
import platform
from sys import argv
from colorama import Fore as c
from itertools import cycle
from argparse import ArgumentParser, BooleanOptionalAction
from modules.analyze_pe import Rizin
from modules.hexdump import hexdump

# Windows logging console
if platform.system() == 'Windows':
    from colorama import just_fix_windows_console
    just_fix_windows_console()


def find_opaque_predicates(data):
    """
    Control Flow Obfuscation through je/jnz opcodes
    - Both jmp addresses resolve to same address, but they confuse the disasm
    """
    je_jne_opcodes = re.compile(b'\x74.\x75.')
    jne_je_opcodes = re.compile(b'\x75.\x74')
    predicates = [je_jne_opcodes, jne_je_opcodes]
    # Store matches for comparison and patching later
    found = []

    # Find matches in binary
    for sig in predicates:
        matches = sig.finditer(data)
        for match in matches:
            found.append(match)
    return found

def patch_opaques(file_name, output="", in_memory=False):
    """
    Use offsets to patch in-memory copy and write new file
    """
    with open(file_name, 'rb') as f:
        data = bytearray(f.read())
    

    matches = find_opaque_predicates(data)

    if len(matches) > 0:
        for match in matches:
            data[match.start()] = 0xEB
            data[match.start()+2] = 0x90
            data[match.start()+3] = 0x90
    if output:
        patched_file = output
    else:
        patched_file = file_name.replace('\\', '').strip().split('.')[1] + '_no_opaques.bin'

    with open(patched_file, 'wb') as f:
        f.write(data)
    
    validate_opaque_patch(file_name, patched_file, matches)

    if in_memory:
        return data

    return patched_file
    
def validate_opaque_patch(original, patched, mods):
    """
    Display to user what bytes were patched, confirming our new file contains different instructions
    """
    orig_rz = Rizin(original)
    patched_rz = Rizin(patched)
    total_patches = len(mods)
    success = 0

    for mod in mods:
        # Display opaque predicate
        print(c.RED + f'[!] Identified opaque predicate!')
        orig_rz.disasm(mod.start())
        old_bytes = orig_rz.get_chunk(mod.start(), 0x2)
        print('-' * 40)
        
        # Display new patched value
        print(c.GREEN + f'[+] Patched value: ')
        patched_rz.disasm(mod.start(), chunk_size=3)
        new_bytes = patched_rz.get_chunk(mod.start(), 0x2)
        
        # Validate we corrected all predicates
        if new_bytes != old_bytes:
            success += 1
        print(c.BLUE + '-' * 64, c.RESET)
        
    if success == total_patches:
        print(c.GREEN + f'[+] Successfully patched ({success}/{total_patches}) opaque predicates\n\n\tPatched file: "{patched}"\n', c.RESET)
        orig_rz.close()
        patched_rz.close()


def patch_problem_funcs(rz: Rizin, blob):
    """
    004014E7:   call [ebx+0x7c]        (90 90 90 90 90)
    00402022:   start of new function  (patch with retn -> C3 90 90 90)
    """
    # Patch : 0x004014E7
    bad_call = rz.get_chunk(0x004014E7, 0x8)
    bad_call_patch = b'\x90' * 5 + bad_call[5:]
    blob = blob.replace(bad_call, bad_call_patch)
    
    # Patch : 0x00402022
    simple_ret = rz.get_chunk(0x00402ED2, 0x8)
    simple_patch = b'\x40' + b'\x90' * 4 + simple_ret[5:]   # inc eax; NOPs
    blob = blob.replace(simple_ret, simple_patch)

    # Patch: 0x004014F2
    bad_call = rz.get_chunk(0x004014F2, 0x8)
    bad_call_patch = b'\x90' * 5 + bad_call[5:]
    blob = blob.replace(bad_call, bad_call_patch)
    

    return blob

def patch_xor_calls(blob):
    """
    Remove calls to XOR function that result in re-encryption:
    - we can leave the decryption calls, since these seem to be fine

    Manual Fix:
        0x00401316 (this expects these values to be set)
            EAX = 0x12E3 (when we patch it still equals 12B0)
            ECX = 0x0
    90 90 90 90 90
    sub_402D18      (RealDeal)
    """
    # Create temp file
    tmp_file = 'stage2_tmp'
    with open(tmp_file, 'wb') as f:
        f.write(blob)

    rz = Rizin(tmp_file)
    # Lets patch one-by-one
    rva_to_patch = [0x004012AB, 0x00401316, 0x00402BFA, 0x00402B58, 0x00402A62, 0x00402B08, 0x00402BB6, 
                    0x00402C77, 0x00402CC5, 0x004029A7, 0x00402A0B, 0x00402D75, 0x00402DBD, 0x00401F7E, 
                    0x00402013, 0x00402E6E, 0x00402EAB, 0x00401A41, 0x00401C0F, 0x004027B5, 0x0040213E,
                    0x004024C4, 0x004023D0, 0x0040246F, 0x00402959, 0x00402064, 0x004014AA, 0x00401981, 
                    0x00401364, 0x00401458, 0x00401549, 0x0040150E]

    for rva in rva_to_patch:
        call_xor = rz.get_chunk(rva, 0x8)
        
        # Patch return args expected for XOR call
        if rva == 0x00401316:
            # patch [push 12B0]     -> push 0x12E3
            push_12B0 = rz.get_chunk(0x004012DA, 0x8)
            blob = blob.replace(push_12B0, b'\x68\xE3\x12\x00\x00' + push_12B0[5:])
            # patch [mov ecx, 0x6b] -> mov ecx, 0x0
            mov_0x6b = rz.get_chunk(0x004012F4, 0x8)
            blob = blob.replace(mov_0x6b, b'\xB9\x00\x00\x00\x00' + mov_0x6b[5:])
        
        # Patch XOR call
        patched = b'\x90' * 5 + call_xor[5:]
        blob = blob.replace(call_xor, patched)
    
    # Patch any remaining problem functions (not XOR related)
    #blob = patch_problem_funcs(rz, blob)
    # Close handles
    rz.close()
    return blob

def decrypt_body(chunk, key):
    
    decrypted_func = b''
    
    for _byte in chunk:
        xored_byte = _byte ^ key
        decrypted_func += struct.pack('B', xored_byte)
    
    return decrypted_func

def decrypt_sections(rz: Rizin, encryped_functions: dict, blob):
    # Decrypt remaining function (second round)
    for offset, function in encryped_functions.items():
        print(c.BLUE + f"[+] Decrypting function at : [{hex(function['rva'])}]", c.RESET)
        enc = rz.get_chunk(function['rva'], function['size'])
        dec = decrypt_body(enc, function['key'])
        blob = blob.replace(enc, dec)
    
    return blob

def decrypt_functions(file_name):
    """
    The majority of the functions for Stage2 are encrypted and we must decrypt, before continuing
    - The offset to calculate the RVA is stored in EAX
    - The size of the function to decrypt is stored in ECX
    - The xor_key to decrypt the function is stored in EDX
    """
    rz = Rizin(file_name)
    with open(file_name, 'rb') as f:
        raw_bin = f.read()
    
    base_address = 0x00400000
    encryped_functions = {
        0x004012AB: {'rva': base_address + 0x12B0,
                     'size': 0x6B,
                     'key': 0x1c},
        0x004014AA: {'rva': base_address + 0x14AF,
                     'size': 0x9F,
                     'key': 0x9B},
        0x0040159F: {'rva': base_address + 0x15A4,
                     'size': 0x387,
                     'key': 0x83},
        0x00401981: {'rva': base_address + 0x1986,
                     'size': 0x6D,
                     'key': 0x0C5},
        0x00401A41: {'rva': base_address + 0x1A46,
                     'size': 0x1CE,
                     'key': 0x55},
        0x00401C58: {'rva': base_address + 0x1C5D,
                     'size': 0x66,
                     'key': 0x32},
        0x00401D0D: {'rva': base_address + 0x1D12,
                     'size': 0x0DD,
                     'key': 0x9B},
        0x00401E41: {'rva': base_address + 0x1E46,
                     'size': 0x0ED,
                     'key': 0x0BE},
        0x00401F7E: {'rva': base_address + 0x1F83,
                     'size': 0x95,
                     'key': 0x0B},
        0x00402064: {'rva': base_address + 0x2069,
                     'size': 0x8A,
                     'key': 0x8D},
        0x0040213E: {'rva': base_address + 0x2143,
                     'size': 0x238,
                     'key': 0x0AD},
        0x004023D0: {'rva': base_address + 0x23D5,
                     'size': 0x9F,
                     'key': 0x0B3},
        0x004024C4: {'rva': base_address + 0x24C9,
                     'size': 0x29C,
                     'key': 0x8A},
        0x004027B5: {'rva': base_address + 0x27BA,
                     'size': 0x1A4,
                     'key': 0x52},
        0x004029A7: {'rva': base_address + 0x29AC,
                     'size': 0x64,
                     'key': 0x48},
        0x00402A62: {'rva': base_address + 0x2A67,
                     'size': 0x0A6,
                     'key': 0x47},
        0x00402B58: {'rva': base_address + 0x2B5D,
                     'size': 0x5E,
                     'key': 0x56},
        0x00402BFA: {'rva': base_address + 0x2BFF,
                     'size': 0x7D,
                     'key': 0x51}
    }

    # These were identified after initial decryption (first round)
    second_round_functions = {
        0x00402CC5: {'rva': base_address + 0x2CCA,
                     'size': 0x0B0,
                     'key': 0x89},
        0x00401364: {'rva': base_address + 0x1369,
                     'size': 0x0F4,
                     'key': 0x21}
    }

    third_round_functions = {
        0x00402DBD: {'rva': base_address + 0x2DC2,
                     'size': 0x0B1,
                     'key': 0x0A1}
    }

    fourth_round_functions = {
        0x00402EAB: {'rva': base_address + 0x2EB0,
                     'size': 0x0CB,
                     'key': 0x0C}
    }
    
    # Decrypt all functions (first round)
    raw_bin = decrypt_sections(rz, encryped_functions, raw_bin)
    
    # Second round
    raw_bin = decrypt_sections(rz, second_round_functions, raw_bin)
    
    # Third round
    raw_bin = decrypt_sections(rz, third_round_functions, raw_bin)

    # Fourth round
    raw_bin = decrypt_sections(rz, fourth_round_functions, raw_bin)

    # Patch XOR
    # raw_bin = patch_xor_calls(raw_bin)
    
    # Total functions patched
    total = len(encryped_functions.keys()) + len(second_round_functions.keys()) + len(third_round_functions.keys()) + len(fourth_round_functions.keys())
    print(c.GREEN + f'[+] Successfully decrypted ({total}) functions! ', c.RESET)
    with open('decrypted_stage2.bin', 'wb') as f:
        f.write(raw_bin)

def extract_final_stage(file_name, BITS='x86'):
    """
    Encrypted/Compressed Stage3 shellcode
    
    gs == 0x2B
    test ax , ax (0x2B)     ; Since we are on a x64 machine, we get the value for the 64bit shellcode

    Shellcode offsets:
    00402F07:   mov     ax, gs              ; Determine whether to use 32bit or 64bit shellcode for stage3
    00402F0A:   test    ax, ax
    00402F0F:   lea     eax, [ebx+33D7h]    ; EBX is our ImageBase (0x400000)
    00402F15:   mov     ecx, 245Ch          ; Size of shellcode to extract

    Decryption key:
    004012B0:   mov     edx, 74F56265h      ; XOR_KEY
    ....
    004012C2:   xor     eax, edx
    """

    rz = Rizin(file_name)
    base_address = 0x00400000
    # 32bit shellcode
    x86_shellcode_offset = base_address + 0x33D7
    x86_shellcode_size = 0x245C
    # 64bit shellcode
    x64_shellcode_offset = base_address + 0x5833
    x64_shellcode_size = 0x2F8E

    # Determine which ARCH to extract (default is x86)
    if BITS != 'x86':
        start = x64_shellcode_offset
        end = start + x64_shellcode_size
        total_size = end - start
    else:
        BITS = 'x86'
        start = 0x004033D7
        end = start + 0x245C
        total_size = end - start
    
    extracted = rz.get_chunk(start, total_size)
    
    if extracted:
        stage_3_name = 'stage3_encrypted_compressed_' + BITS + '.bin'
        print(c.GREEN + f'[+] Extracted stage3 payload successfully! Writing to: "{stage_3_name}"', c.RESET)
        with open(stage_3_name, 'wb') as f:
            f.write(extracted)

def xor(data, dw_key):
    """
    This function is decrypted after our first XOR_CHUNK
    It starts the decryption of a large buffer at the end of the payload
    Credit: OALabs
    """
    if isinstance(dw_key, int):
        key = bytes([dw_key])
    return bytes([a ^ b for a, b in zip(data, cycle(dw_key))])


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", help="Malware to analyze", metavar='', required=False)
    parser.add_argument('-op', "--opaques", action='store_true', help='Patch opaque predicates')
    parser.add_argument('-df', '--decryptfuncs', action='store_true', help='Decrypt encrypted functions')
    parser.add_argument('-ext', '--extract', action='store_true', help='Extract encrypted/compressed stage3 payload')

    args = parser.parse_args()

    if args.file == None:
        parser.print_help()
        exit(0)
    print(c.YELLOW + "[!] Starting analysis on : ", args.file, c.RESET)
    if args.opaques:    
        patch_opaques(args.file)
    elif args.decryptfuncs:
        # Handle XOR decryption
        decrypt_functions(args.file)
        # Handle new predicates after decryption
        patch_opaques('decrypted_stage2.bin', output='decrypted_stage2_no_opaques.bin')

    elif args.extract:
        # Stage3
        extract_final_stage(args.file)
    else:
        print(args.file, args.decryptfuncs)
