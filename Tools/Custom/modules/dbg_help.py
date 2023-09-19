import os, psutil
import subprocess
from colorama import Fore as c
from colorama import just_fix_windows_console
from platform import system as get_os

if get_os == 'Windows':
    just_fix_windows_console()


def inject_hook(target):

    try:
        pid = int(target)
        args = [".\\Mod\\InjectorCLIx86.exe", "pid:" + str(pid) ,  '.\\Mod\\HookLibraryx86.dll', 'nowait']
        result = subprocess.run(args, shell=True, capture_output=True)
    except ValueError:
        args = [".\\Mod\\InjectorCLIx86.exe", target , '.\\Mod\\HookLibraryx86.dll', 'nowait']
        result = subprocess.run(args, shell=True, capture_output=True)

    if result.stderr:
        print(c.RED + "[-] Error loading hook into process", c.RESET)
        return

    results = result.stdout.decode()

    if 'Cannot open process' in results:
        print(c.RED + '[-] Need higher permissions to inject! Try from an Administrator prompt.', c.RESET)
        return
    elif 'Usage:' in results:
        print(c.RED + '[-] We really messed this up... Check your syntax and verify your process_name or PID!', c.RESET)
        return
    
    print(c.GREEN + result.stdout.decode(), c.RESET)

def get_pid(proc_name):
    for proc in psutil.process_iter():
        if proc_name.lower() in str(proc.name).lower():
            return str(proc.pid)



if __name__ == "__main__":
    inject_hook('6548')
