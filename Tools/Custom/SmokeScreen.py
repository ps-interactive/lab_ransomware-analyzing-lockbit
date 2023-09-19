"""
"""
import pyfiglet
import cmd
from colorama import Fore as c
from modules.hexdump import hexdump
from modules.mem_scrubber import MemoryScrubber
from modules.dbg_help import inject_hook, get_pid
from modules.analyze_pe import Rizin
from modules.win32mem import MemoryMap

banner = c.GREEN + pyfiglet.figlet_format("Smoke", font='thick')


class SmokePrompt(cmd.Cmd):
    intro = banner + "\nWelcome.. Type help or ? to list commands.\n"
    prompt = c.BLUE + "(" + c.WHITE + "SmokeScreen" + c.BLUE + ")=> " + c.RESET
    file = None
    
    def do_get_pid(self, arg):
        """
        Get process id (PID) for process name
        """
        args = arg.split()

        if len(args) < 1:
            print(c.RED + "[-] Must supply valid process name (get_pid stage1.exe)", c.RESET)
        else:
            print(c.GREEN + 'PID: ', get_pid(args[0]))

    def do_scan_memory(self, arg):
        args = arg.split()
        try:
            pid = int(args[0])
            # Init manager
            m = MemoryMap(pid)
            # Identify payload
            m.scan_memory(pid)
            
            # Extract payload
            if len(m.extracted_image) > 1:
                print(c.GREEN, f'[+] Extracted image {len(m.extracted_image)} bytes in size!')
                hexdump(m.extracted_image[:50])
                print(c.RESET)
                # Clean Payload
                with open('mem_stage2.bin', 'wb') as f:
                    f.write(m.extracted_image)
                
                scrub = MemoryScrubber('mem_stage2.bin')
                scrub.deflate()


        except ValueError:
            print(c.RED + "[-] Bad PID given.. Expected: (dump_memory <pid>)")
            return


    def do_inject_hook(self, arg):
        args = arg.split()
        if len(args) < 1:
            print(c.RED + "[-] Must supply either PID or process name (inject_hook stage1.exe)", c.RESET)
        else:
            inject_hook(args[0])

    def do_rizin(self, arg):
        args = arg.split()
        try:
            rz = Rizin(args[0])
            rz.prompt()
        except:
            print(c.RED, "[-] Bad input given... Expected (rizin <file_name>)")
        
    def do_defobufscate(self, arg):
        pass
    
    def upload_patch(self, arg):
        pass


if __name__ == "__main__":
    s = SmokePrompt()
    s.cmdloop()
