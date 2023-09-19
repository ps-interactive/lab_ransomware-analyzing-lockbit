"""
This tool was developed to clean Stage1 for sample:
    - SmokeLoader: a88d2d74d7359c8b74e1f85fa6fd4fbb 

It looks for the shellcode extracted from the dumped memory page then calls the "shcode2exe" code
to create the PE from the shellcode.

[+] Shellcode to EXE w/ NASM
    Credit: https://github.com/accidentalrebel/shcode2exe/blob/master/shcode2exe.py
    Modified by: elusivethreat

    Requirements:
        - (choco install nasm)
        - (choco install mingw)
"""

import os
import shutil
import subprocess
import platform
from colorama import Fore as c
from argparse import ArgumentParser

# Windows logging console
if platform.system() == 'Windows':
    from colorama import just_fix_windows_console
    just_fix_windows_console()


def CheckRequirementsMet(arg_vars):
    # NASM Default Path
    nasm_path = "C:\\Program Files\\NASM\\;"

    # LD Default Path:
    linker_path = "C:\\ProgramData\\chocolatey\\lib\\mingw\\tools\\install\\mingw64\\x86_64-w64-mingw32\\bin\\;"
    
    # Patch path for NASM/LD
    old_path = os.environ['PATH']
    os.environ['PATH'] = nasm_path + linker_path + old_path
    
    requirements = ['ld','nasm']
    for prog in requirements:
        if shutil.which(prog) is None:
            if prog == 'ld':
                print("{} is not installed or found. Ensure it is installed (e.g. 'sudo apt install binutils') and in your PATH and try again.".format(prog))
            elif prog == 'nasm':
                print("{} is not installed or found. Ensure it is installed (e.g 'sudo apt install nasm') and in your PATH and try again.".format(prog))
            else:
                print("Unmatched or unidentified requirements")
            raise SystemExit(1)
    CompileShellCode(arg_vars)

def ConvertToBin(file_input, filename):
    with open(file_input, 'r', encoding='unicode_escape') as input_file:
        s = input_file.read().replace('\n', '')
        with open(filename + '.bin', 'wb') as gen_file:
            gen_file.write(b'' + bytes(s, encoding='raw_unicode_escape'))
            file_input = filename + '.bin'
    input_file.close()
    gen_file.close()
    return file_input

def CompileShellCode(arguments):
    if arguments['output']:
        filename = os.path.basename(arguments['output']).split('.')[0]
    else:
        filename = 'output'

    file_input = arguments['input']

    if file_input and not os.path.exists(file_input):
        print('ERROR: File {} does not exist!'.format(file_input))
        raise SystemExit(1)

    if arguments['string']:
        file_input = ConvertToBin(file_input, filename + '-gen')
        if arguments['verbose']:
            print("Converting input file to {}-gen.bin".format(filename))

    asm_file_contents = '\tglobal _start\n' \
        '\tsection .text\n' \
        '_start:\n' \
        '\tincbin "' + file_input + '"\n'

    if arguments['verbose']:
        print(c.YELLOW +  "[!] Writing assembly instruction to {}.asm".format(filename))
    with open(filename + '.asm', 'w+') as f:
        f.write(asm_file_contents)

    nasm_bin = 'nasm -f win' + arguments['architecture'] + ' -o ' + filename + '.obj ' + filename + '.asm'
    if arguments['verbose']:
        print("[!] Executing: {}".format(nasm_bin))
    subprocess.check_output(nasm_bin, shell=True)

    ld_bin = 'ld'
    if arguments['architecture'] == '32':
        ld_bin = ld_bin + ' -m i386pe -o '
    elif arguments['architecture'] == '64':
        ld_bin = ld_bin + ' -m i386pep -o '

    if arguments['output']:
        ld_bin += arguments['output']
    else:
        ld_bin += filename + '.exe'

    ld_bin += ' ' + filename + '.obj'
    if arguments['verbose']:
        print("[!] Executing: {}".format(ld_bin))
    subprocess.check_output(ld_bin, shell=True)
    if arguments['verbose']:
        print(c.GREEN +  "[+] Compiled shellcode saved as {}".format(filename))

    if not arguments['keep']:
        if arguments['verbose']:
            print(c.YELLOW +  "[!] Cleanup: attempting to remove {0}.obj, {0}.asm, and {0}-gen.bin (if present)".format(filename), c.RESET)
        os.remove(filename + '.obj')
        os.remove(filename + '.asm')

        if os.path.exists(filename + '-gen.bin'):
            os.remove(filename + '-gen.bin')

def main(arg_vars):
    
    # Program Start
    """
    parser = ArgumentParser(description='Compile shellcode into an exe file from Windows or Linux.')
    parser.add_argument('-o',
                        '--output',
                        help='Set output exe file.')
    parser.add_argument('-s',
                        '--string',
                        action='store_true',
                        help='Set if input file contains shellcode in string format.')
    parser.add_argument('-a',
                        '--architecture',
                        choices=['32', '64'],
                        default = '32',
                        help='The windows architecture to use')
    parser.add_argument('-k',
                        '--keep',
                        action='store_true',
                        help='Keep files used in compilation')
    parser.add_argument('-V',
                        '--verbose',
                        action='store_true',
                        help='Print actions to stdout')
    parser.add_argument('input',
                        help='The input file containing the shellcode.')
    args = parser.parse_args()

    #arg_vars = vars(args)
    """
    CheckRequirementsMet(arg_vars)


def clean_payload(file_name):
    """
    This removes junk bytes from payload based on offset from analysis
    """
    stage1_start = b'\xE8\x01\x00\x00\x00\xC3'
    
    with open(file_name, 'rb') as f:
        data = f.read()

    start = data.find(stage1_start)    

    cleaned = data[start:]

    with open('Stage1_offset.bin', 'wb') as f:
        f.write(cleaned)
    
    shellcode_attribs = {'verbose': True, 'input': 'Stage1_offset.bin', 'architecture': '32', 'output': 'CustomPE.exe', 'string': '', 'keep': False}
    
    CheckRequirementsMet(shellcode_attribs)

    # Cleanup our original file
    if os.path.exists('Stage1_offset.bin'):
        os.remove('Stage1_offset.bin')


if __name__ == "__main__":
    parser = ArgumentParser()

    parser.add_argument('-f', '--filename', help='Shellcode file to clean', metavar='')

    args = parser.parse_args()

    if args.filename:
        clean_payload(file_name=args.filename)
    else:
        parser.print_help()
