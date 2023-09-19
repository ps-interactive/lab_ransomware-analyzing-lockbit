"""
When dumping the module it has alot of padding that is added once its loaded into memory, if we are to modify
the image we need to remove the padding to analyze in IDA, then add it again to re-inject into the 
current debug session in IDA
"""

first_byte = b'\x18\x6E\x5D\xB9'    # Location: 0x1000
last_byte = b'\xF4\x93\x95\x8D'     # Location: 0x7B0
entry_point = b'\xE8\x00\x00\x00'

import os
import pefile
from modules.hexdump import hexdump
from modules.analyze_pe import Rizin
from binascii import unhexlify, hexlify
from colorama import Fore as c


class MemoryScrubber:
    def __init__(self, file_name) -> None:
        self.file = file_name
        self.pe = pefile.PE(file_name, fast_load=False)
        self.loader = Rizin(file_name)

    def get_entry(self):
        pe_info = self.pe.dump_dict()

        BaseAddress = pe_info['OPTIONAL_HEADER']['ImageBase']['Value']
        EntryPoint_offset = pe_info['OPTIONAL_HEADER']['AddressOfEntryPoint']['Value']

        EntryPoint = (BaseAddress + EntryPoint_offset)
        # Corrupt Header?
        #data = pe.get_data(EntryPoint, 0x4)
        data = self.loader.get_chunk(EntryPoint, 0x4)
        hexdump(data)

    def get_patched_payload(self, patched_file):
        """
        Carve out .text section to craft new "inflated" payload 
        for final delivery 
        """
        with open(patched_file, 'rb') as f:
            data = f.read()
        
        text_start = data.find(first_byte)
        text_end = data.find(last_byte) + 4

        return data[text_start : text_end]

    def inflate(self, payload):
        """
        After 20 00 00 E0 in text:
        - 6 rows of 16 bytes (0x00) before start of text section

        After F4 03 05 8D:
        - 3 rows of (0x00) + 3 bytes (0x0)
        """
        # Get good header from original dumped payload
        with open(self.file, 'rb') as f:
            data = f.read()
        
        # Inflated Header
        text_section = data.find(first_byte)
        pe_header = data[:text_section]
        # Inflated Footer
        end = data.find(last_byte) + 4
        pe_footer = data[end:]
        
        # Payload start
        start_of_payload = payload.find(first_byte)
        end_of_payload = payload.find(last_byte) + 4
        # New Payload
        inflated_payload = pe_header
        inflated_payload += payload[start_of_payload:end_of_payload]
        inflated_payload += pe_footer

        with open('ReadyToPatch.bin', 'wb') as f:
            f.write(inflated_payload)
        
        rz = Rizin('ReadyToPatch.bin')
        ep = rz.get_chunk(0x40324c, 0x4)
        hexdump(ep)
        assert ep == b'\xBE\x5C\xEA\x49'

        print(c.GREEN + '[+] Successfully inflated payload! Ready to inject back into process!\n -> ReadyToPatch.bin', c.RESET)
    
    def deflate(self):
        """
        Our EntryPoint(0x40324C) should point to (E8 00 00 00 00)
        """
        deflated_header = b'4d5a80000100000004001000ffff00004001000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0a240000000000000000504500004c0101005c2f97630000000000000000e0000f010b0101480078000000000000000000004c32000000100000000000000000400000100000000200000100000000000000050001000000000000900000000200003f0001000200000000100000001000000000010000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e74657874000000cd770000001000000078000000020000000000000000000000000000200000e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        deflated_footer = b'000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'

        with open(self.file, 'rb') as f:
            data = f.read()

        active_dump = Rizin(self.file)
        print(c.YELLOW + '[!] Current EntryPoint: ')
        ep = active_dump.get_chunk(0x40324c, 0x4)
        hexdump(ep)
        active_dump.disasm(0x40324c, chunk_size=0x2, rva=True)

        start_index = data.find(first_byte)
        end_index = data.find(last_byte) + 4

        pe_body = data[start_index:end_index]

        new_payload = unhexlify(deflated_header)
        new_payload += pe_body
        new_payload += unhexlify(deflated_footer)

        with open("deflated.bin", 'wb') as f:
            f.write(new_payload)

        rz = Rizin('deflated.bin')

        new_entry = rz.get_chunk(0x40324c, 0x4)

        try:
            assert new_entry == b'\xE8\x00\x00\x00'
        except AssertionError:
            print(c.RED + '[-] Failed to clean memory dumped module!', c.RESET)
            # Close file first, avoids permission error
            rz.close()
            if os.path.exists('deflated.bin'):
                os.remove('deflated.bin')

        print(c.GREEN + f'[+] Successfully cleaned module "{self.file}" as : "deflated.bin"', c.RESET)
        print(c.GREEN + '[+] New EntryPoint: ')
        hexdump(new_entry)
        rz.disasm(0x40324c, chunk_size=0x2, rva=True)
        print(c.RESET)
    
