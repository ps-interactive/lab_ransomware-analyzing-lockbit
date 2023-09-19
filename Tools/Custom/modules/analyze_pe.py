import os
import rzpipe
import sys
import json
import pefile
import logging
from colorama import Fore as c
from argparse import ArgumentParser
from pprint import pprint
from binascii import unhexlify, hexlify


class Rizin:
    def __init__(self, file_name) -> None:
        self.file_name = file_name
        self.pe = pefile.PE(file_name, fast_load=False)
        self.rz_conn = None
        self.json_data = {}
        self.init_rz()
        self.init_function_data()


    def init_rz(self):
        try:
            # Fix rz_yara dl_open issue; we don't need this plugin so we can remove it
            os.rename("C:\\ProgramData\\chocolatey\\lib\\cutter\\tools\\Cutter-v2.2.1-Windows-x86_64\\lib\\plugins\\rz_yara.dll", "C:\\ProgramData\\chocolatey\\lib\\cutter\\tools\\Cutter-v2.2.1-Windows-x86_64\\lib\\plugins\\rz_yara.dll.bck")
        except FileNotFoundError:
            pass
        self.rz_conn = rzpipe.open(self.file_name)
        self.rz_conn.cmd('aaa')
        self.rz_conn.cmd("e scr.color=1")
        self.rz_conn.cmd("eco onedark")
    
    def generate_xrefs(self, entry):
        """
        Get XREFs for single function
        """
        
        xrefs = self.rz_conn.cmd(f"axtj @ {hex(entry['offset'])}")
        json_loaded_xrefs = json.loads(xrefs)
        xref_list = []
        for xref in json_loaded_xrefs:
            xref_data = {}
            xref_data['from'] = xref['from']
            if "name" in xref:
                xref_data["fcn_name"] = xref["name"].split("+")[0]
            elif "fcn_name" in xref:
                xref_data["fcn_name"] = xref["fcn_name"]
            
            xref_list.append(xref_data)
        
        return xref_list
    
    def init_function_data(self):
        json_func_data = json.loads(self.rz_conn.cmd("aflj"))

        for entry in json_func_data:
            entry_data = {}
            entry_data['name'] = entry['name']
            entry_data['offset'] = entry['offset']
            entry_data['size'] = entry['size']
            xrefs = self.generate_xrefs(entry)
            entry_data['xrefs'] = xrefs
            self.json_data[entry['offset']] = entry_data

    def display(self):
        for start_addr, func_info in self.json_data.items():
            print(hex(start_addr), func_info)

        offset = self.json_data[0x40324c]['offset']
        size = self.json_data[0x40324c]['size']
        print(self.pe.DOS_HEADER)
        print("Using offset: and size: ", offset, size)
        d = self.pe.get_data(offset, size)
        print(d)
    
    def get_chunk(self, rva, size):
        chunk = self.rz_conn.cmd(f'p8 {size} @ {rva}').strip()
        raw = unhexlify(chunk)
        return raw
    
    def prompt(self):
        while True:
            try:
                cmd = input(c.BLUE + "(rz)==> ")
                response = self.rz_conn.cmd(cmd)
                print(response)
            except KeyboardInterrupt:
                print("Closing session")
                break
    
    def disasm(self, file_offset, chunk_size=2, rva=False):
        """
        Disassmble chunk
        """
        if not rva:
            # Change to non-VA mode
            self.rz_conn.cmd('e io.va=0')
        
        # Seek to file offset
        self.rz_conn.cmd(f's {file_offset}')
        
        # Disassembly bytes
        disasm_bytes = self.rz_conn.cmd(f'pd {chunk_size}')
        print(disasm_bytes)

    def close(self):
        """
        Close all files
        """
        self.rz_conn.quit()


if __name__ == "__main__":
    """
    .text section starts at 0x00401000
    """

    parser = ArgumentParser()
    parser.add_argument("-f", "--file", metavar="", help="File to load")

    args = parser.parse_args()

    if args.file:
        rz = Rizin(args.file)
        rz.prompt()    
    else:
        print(parser.print_help())
