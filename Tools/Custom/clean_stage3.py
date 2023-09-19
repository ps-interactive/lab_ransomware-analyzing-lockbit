import logging
import struct
import sys
import structlog
import unicorn
import platform
from argparse import ArgumentParser
from binascii import unhexlify
from itertools import cycle
from contextlib import suppress
from colorama import Fore as c
from modules.unicorn_pe_loader import InitUnicorn
from conf_extract import analyze_stage3
# Windows logging console
if platform.system() == 'Windows':
    from colorama import just_fix_windows_console
    just_fix_windows_console()

"""
The LZSA algorithm is based on : https://github.com/emmanuel-marty/lzsa/tree/master
    - Note: I tried using the lzsa.exe from the Releases section and it failed with "invalid magic number"
    - I did confirm it was this algorithm by finding 3 functions in the malware matching: https://github.com/emmanuel-marty/lzsa/blob/master/asm/x86/decompress_small_v2.asm

This code was pulled from main.py (from the smoke_conf_extract repo) and adopted to create a standaonline tool to decompress
w/ LZSA for SmokeLoader

Credit: 
    - https://github.com/myrtus0x0/smoke_conf_extract
    - https://research.openanalysis.net/smoke/smokeloader/loader/config/yara/triage/2022/08/25/smokeloader.html#Destroyed-PE-Format

    Modifications: elusivethreat
"""
# Hexlified decompress_client.pe_file
decompress_client = b'4d5a80000100000004001000ffff00004001000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0a240000000000000000504500004c010100b95c8a610000000000000000e0000f010b010148007200000000000000000000d82d00000010000000000000000040000010000000020000010000000000000005000100000000000090000000020000270a01000200000000100000001000000000010000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e746578740000001c700000001000000072000000020000000000000000000000000000200000e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000058a1cef2ae5fa2ab585ecaafad135d8bee3d1620d2204080c0104c0f3e0f6a174c5da878d8278abefeba73a8c09f08c174c405364b5a599cb7e2ca974dccfa16b60ebc244ffcb97683f229ecb4b6c511c16d6828fe6d760dc2de2efbfad1d02fa1d9dfb6d5e6e9c67ec4196d2b8f7ea0128d229709484890eba0faba519006f19e4ecefec3514264e4c88a2174707b3fa5f8ed1634e56c65567a455fe1c6d8f4b2b7841c47805ef4dfad813765958fc5efb0db3a1a17888407e95671dd9f9ff6883f864ce9040b5426a692f7d57261f0f682a4fabfb483d3be9e7913f1793262ed51f3a3002dc1240996ac573f820bf724cc166d7231d5f5dd3f3b5a1a82146bf23ef80267356a4ea16217aef66d82876a5ba717fbdfc00ba0adc176baf4199d341a3f2b39dc45946e3bf886c2f27af4c8416a10fc127a7ab136c13997a18d1274087506bc4dd2b71f62897c24fc83ec0474077505e30c12f68e83ec04893424eb0d0c1cae68fe0840605aeb056925ebf43ae8000000007506740406f9ce7e8b342483c404eb0a4c81ee77110000eb052aebf54c2aeb05406219006001c6eb0ad0782d75565feb059548ebf8d5aceb05484b19006030d0aae2f37505740382c40e8b342483c404750574033be5d95fc35589e55657eb0fb03dce7a6c680512000058eb05e98febf455eb12c8978ea23bc06a4d8b0c2483c404eb057238ebf2e5e83bffffff4400f6be9e75b3f2758bf67709af3f17fc53cf2e551c04a77d1ffd8af852ce2e541c0415f36affed96fbecfefea615fb9d6b150a6215f0cac17cd3a647b3fefefe15fba1d4150b2516100001015f5ec9c208005589e555535657eb12bf8a9468921200008b042483c404eb0519d4ebeffaeb126bac5268e50000008b0c2483c404eb05a5daebefc1e8aefeffffab758bf67583f2cf250039cf13cf3e52f1482edae63e16fdc2fd8bec167bfefefefe36c2ec8bf952faec8dfc98536f0d5a083c3e86e76f8bf47e04de16a8fefefe15f6520032083cde8ae3003215e784f07e045e781e16c2fefefed2fc15f8083cde8bfb52781e526b6cdaf9fafcc2f78bea16d1fefefefe36c2e68bf752fae68dfa8acc98536f68f14113738ac3fe0d5a6817880101010b2e2616f9fefefef6362e3eca1f3d082187fd6d526d4ffa2c354ff1de273da3d583f215f017d86a7f966cecfefea615fbc907150a7c15f07f2d0cee8e471bfefefe15fbb7c9150b9f163703010189f85f5e5b5dc9c208005589e583ec0c535657eb0f1fe6e0f54568b513000058eb05fef4ebf4f3eb0d35be7d689600000059eb05fb83ebf4bce88bfdffff75a3f6cf3e77bb0a75b3ea77ff758bf27583eea9a8a9a816010301015373ab0677fc73ab0277fc73bb0acf3794fa96fecefefeacafae940101ad827b3e8beb018b0aa816a5000101c5bb068bf975b3ea77ff15f939bb0afefefefea0a1a9a8164903010115eb6fa4626c05b4964bedfefe75fada7d3afa15fb652315115115f0f2234bf59668fefefea715fb23df150a02160b0201018b45f45f5e5bc9c210005589e583ec60535657eb0cad8d98b88c140000eb05baf4ebf5baeb138bec012e68790300008b0c2483c404eb05e928ebef75e8b4fcffff75a3f6cf01778332987216987b3e8afd01bb3201adb67b3ef17ae3fdfefe77bb5a738b5e77c0a8ae01adb275f87b3ef17afafdfefe73b32e77ff7787fa738b2694e6a801adee39f8e6fefefe770c73b32e73bb0eafac94beae01ad8e7b3ef17b2bfcfefe73bb0a94fca9a9ae94019401018b0e016d7efefefe7b3ef17b46fcfefe77830673bb4e7786fa39fefeaefefe738b52a996fefefef694faaea994f8a801ad8a7b3e8ba4018b4e71bb3673bb4277c673b33694faa994ffafa9a9a9ae940101c801ad867b3e8bc973bb3a77c673b33694faa994ffafa9a9a9ae018b0a01c801ad867b3e8be7758b4296fafffefea8a901adde75bbea7778f6fcfefe01bb0673bb4e75b3ee7f3ffefefffe7786fa77f6738b56a996fefefef694beaea994f0a801ad8a7b3ef17bf2fcfefe7d8306fef17afcfcfefe018b4e71bb3673bb4677c673b33694faa994ffafa9a9a9ae940101c801ad867b3ef17b25fffefe73bb3e77c673b33694dea994ffafa9a9a9ae018b0a01c801ad867b3ef17b47fffefe16fefefefe8bfa8afc7e5675cada7d3afa15f43a7f10efe8fefe15fb7c150b3a7c15fb3634e0fe9e7f38fbacfefe15eef3216c4869da96f5d0fefea715fb4741150a0e15eaa334848150969edcfefe75eada7d3afa15fbad6715114415f557f58a896faca615fb5dc715064815ffe63f1cfb15fbb685e0fe9eff3c15fbbe8ee0fe9ecf3e15ffb05215fbba9be0fe9eff3c15ff9a1c3815fbbaa9e0fe9e7f0ce9e4542615f8b6d72a15fbf61507b6f6758bf2fdc8f149b0f8a8770c7d8332fe8af67f3cf6fffefe15f87f3c06fefefeaf75b4ee7b378af07584f2fd8346758ceafd8bf20d5a7d3cd6a71c1aa07d8332fe8a9816fefefefea17f11fde9fefe770777047f3f61d5fefe7f3cc9e9fefe77f47706fb61d5fefe96a8fffefeae165c04010175bb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000056032697fe08406070756233000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'

def init_logger():
    renderer = structlog.dev.ConsoleRenderer()
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            renderer,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.INFO)
    return


def emulate_decompress_call(emulator:InitUnicorn, start_func, end_func, compressed_data, decompressed_size):
    logger = structlog.get_logger(__name__)

    logger.info("starting emulation", start_addr="0x%x" % start_func, end_func="0x%x" % end_func)

    # reset stack
    logger.info("setting stack and regs")
    emulator.create_stack()

    decompressed_addr = 0x70000000

    # ensure our given section is unmapped at start
    with suppress(unicorn.UcError):
        emulator.mu.mem_unmap(decompressed_addr, 32 * 1024)

    emulator.mu.mem_map(decompressed_addr, 32*1024)
    emulator.push_arg(decompressed_addr)

    # write our data to be decompressed
    compressed_addr = 0x80000000

    # ensure our given section is unmapped at start
    with suppress(unicorn.UcError):
        emulator.mu.mem_unmap(compressed_addr, 32 * 1024)

    emulator.mu.mem_map(compressed_addr, 32*1024)
    emulator.mu.mem_write(compressed_addr, compressed_data)
    emulator.push_arg(compressed_addr)
    emulator.push_arg(0)
    emulator.init_regs()

    try:
        emulator.mu.emu_start(start_func, end_func, timeout=120 * unicorn.UC_SECOND_SCALE)
    except unicorn.UcError as e:
        logger.error("error during emulation", error=e)
        decompressed_data = emulator.mu.mem_read(decompressed_addr, decompressed_size)
        return decompressed_data

    decompressed_data = emulator.mu.mem_read(decompressed_addr, decompressed_size)
    return decompressed_data


def decompress_buffer(emulator:InitUnicorn, decrypted_stage_3):
    logger = structlog.get_logger(__name__)
    decompressed_size = struct.unpack("I", decrypted_stage_3[:4])[0]
    logger.info("decompressed info", decompressed_size="0x%x" % decompressed_size)

    decrypted_stage_3 = decrypted_stage_3[4:]
    start_func = 0x00401258
    end_func = 0x0040137E
    size_func = end_func - start_func
    logger.debug("func info", addr="0x%x" % start_func, size=size_func)
    return emulate_decompress_call(emulator, start_func, end_func, decrypted_stage_3, decompressed_size)


def xor(key, data):
    """
    Credit: myrtus0x0
    """
    if isinstance(key, int):
        key = bytes([key])
    return bytes([a ^ b for a, b in zip(data, cycle(key))])


def decrypt_dw(data, dw_key, byte_key):
    """
    Credit: OALabs
    """
    out = b''
    for i in range(0,(len(data)//4)*4,4):
        tmp = struct.unpack('<I', data[i:i+4])[0]
        out += struct.pack('<I', tmp ^ dw_key)
    # Decrypt tail
    tail_bytes = len(data) % 4
    if tail_bytes > 0:
        tmp_out = []
        for c in data[-tail_bytes:]:
            tmp_out.append(c ^ byte_key)
        out += bytes(tmp_out)
    return out


def decompress_stage3(decrypted_stage_3, output_file=None):
    """
    Utilizes the unicorn emulator to execute the decompression algorithm that is stored in the decompress_client blob
    """
    logger = structlog.get_logger(__name__)
    
    decompress_emulator = InitUnicorn(unhexlify(decompress_client), logger, type_pe=True, bit=32, debug=False)

    decompressed_data = decompress_buffer(decompress_emulator, decrypted_stage_3)
    if decompressed_data is None:
        logger.error("unable to decompress data")
    
    if output_file:
        print(c.GREEN + f'[+] Writing decompressed file to : {output_file}')
        with open(output_file, 'wb') as f:
            f.write(decompressed_data)
        
    return decompressed_data


def patch_pe_header(stage3_shellcode):
    """

    """
    pe_header = b'4d5a80000100000004001000ffff00004001000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0a240000000000000000504500004c0101005c2f97630000000000000000e0000f010b0101480078000000000000000000004c32000000100000000000000000400000100000000200000100000000000000050001000000000000900000000200003f0001000200000000100000001000000000010000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e74657874000000cd770000001000000078000000020000000000000000000000000000200000e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    start_of_code = b'\xC7\xA4\xAB\x2F'     # 0x400h offset
    start = stage3_shellcode.find(start_of_code)
    assert start == 0x400
    new_pe = unhexlify(pe_header) + stage3_shellcode[start:]
    with open('FirstTry_Stage3.bin', 'wb') as f:
        f.write(new_pe)
    

def patch_stage_3(stage3_file, output_file=None):
    """
    Stages to patch:
    - decrypt
    - decompress
    - patch missing PE header (Not implemented)

    Resources:
        DWORD XOR Encryption:   (https://research.openanalysis.net/smoke/smokeloader/loader/config/yara/triage/2022/08/25/smokeloader.html#Extract-Stage-3)
        LZSA Compression:       (https://github.com/myrtus0x0/smoke_conf_extract/blob/main/main.py#L107)
        Missing PE Header:      (https://m.alvar.es/2020/06/unpacking-smokeloader-and.html#)

    """
    # Load stage3
    with open(stage3_file, 'rb') as f:
        stage3_shellcode = f.read()
    
    # First phase (XOR decryption)
    XOR_KEY = 0x74F56265
    XOR_KEY_LAST_BYTE = 0x65
    
    # Two different methods, same end result? 
    # These techniques provide the same results for the x86 shellcode, but the last byte is different for the x64 shellcode??
    decrypted_stage3 = decrypt_dw(stage3_shellcode, XOR_KEY, XOR_KEY_LAST_BYTE)     # OALabs
    other_dec = xor(b'\x65\x62\xF5\x74', stage3_shellcode)                          # myrtus0x0
    
    # This should pass; since we are doing x86 only for now
    assert decrypted_stage3 == other_dec

    # Second phase (LZSA decompression)
    raw_stage3 = decompress_stage3(decrypted_stage3)
    
    # Third phase (Patch PE Header w/ LIEF)
    if output_file:
        print(c.GREEN + f'\n[+] Successfully decrypted and decompressed stage3 payload!\n\tWriting to: "{output_file}"', c.RESET)
        with open(output_file, 'wb') as f:
            f.write(raw_stage3)
    else:
        return raw_stage3
    

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", help="Malware to analyze", metavar='', required=False)
    parser.add_argument('-d', '--decompress', action='store_true', help='Decompress file with LZSAv2. Make sure payload is already decrypted')
    parser.add_argument('-a', '--all', action='store_true', help='Do all the tasks to fix payload: (decrypt, decompress)')
    parser.add_argument('-conf', '--config', action='store_true', help='Extract the configuration from cleaned Stage3 payload')

    args = parser.parse_args()

    if args.file == None:
        parser.print_help()
        exit(0)

    print(c.YELLOW + f"[!] Starting analysis on : {args.file}\n", c.RESET)

    if args.decompress:
        decompress_stage3(args.file, output_file="decompressed_stage3.bin")
    
    elif args.all:
        patch_stage_3(args.file, output_file="Stage3.bin")
    elif args.config:
        analyze_stage3(args.file)
    else:
        parser.print_help()
