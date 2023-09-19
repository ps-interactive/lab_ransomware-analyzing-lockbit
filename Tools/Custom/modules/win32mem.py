import ctypes
import ctypes.wintypes
import pefile
from ctypes import windll
from ctypes.wintypes import BOOL, WORD, DWORD, HANDLE, LPVOID, LPCVOID, ULONG, LPSTR
from ctypes import Structure, byref, sizeof, WinError
from colorama import Fore as c
from colorama import just_fix_windows_console
from platform import system
from modules.hexdump import hexdump

if system() == 'Windows':
    just_fix_windows_console()

"""
References:
 - https://github.com/thezdi/scripts/blob/master/python_injector.py
 - https://stackoverflow.com/questions/75838756/python-process-memory-detecting
 - https://github.com/nccgroup/memaddressanalysis/blob/master/Windows/memanalysis.py

"""
# Define Win32 Constants
LPCSTR = LPCTSTR = ctypes.c_char_p
LPDWORD = PDWORD = ctypes.POINTER(DWORD)
SIZE_T = ULONG_PTR = ctypes.POINTER(ULONG)

DELETE = 0x00010000                         #  Required to delete the object.
READ_CONTROL = 0x00020000                   #  Required to read information in the security descriptor for the object, not including the information in the SACL. To read or write the SACL, you must request the ACCESS_SYSTEM_SECURITY access right. For more information, see SACL Access Right.
SYNCHRONIZE = 0x00100000                    #  The right to use the object for synchronization. This enables a thread to wait until the object is in the signaled state.
WRITE_DAC = 0x00040000                      #  Required to modify the DACL in the security descriptor for the object.
WRITE_OWNER = 0x00080000                    #  Required to change the owner in the security descriptor for the object.
PROCESS_CREATE_PROCESS = 0x0080             #  Required to create a process.
PROCESS_CREATE_THREAD = 0x0002              #  Required to create a thread.
PROCESS_DUP_HANDLE = 0x0040                 #  Required to duplicate a handle using DuplicateHandle.
PROCESS_QUERY_INFORMATION = 0x0400          #  Required to retrieve certain information about a process, such as its token, exit code, and priority class = see OpenProcessToken #.
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000  #  Required to retrieve certain information about a process = see GetExitCodeProcess, GetPriorityClass, IsProcessInJob, QueryFullProcessImageName #. A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted PROCESS_QUERY_LIMITED_INFORMATION.  Windows Server 2003 and Windows XP:  This access right is not supported.
PROCESS_SET_INFORMATION = 0x0200            #  Required to set certain information about a process, such as its priority class = see SetPriorityClass #.
PROCESS_SET_QUOTA = 0x0100                  #  Required to set memory limits using SetProcessWorkingSetSize.
PROCESS_SUSPEND_RESUME = 0x0800             #  Required to suspend or resume a process.
PROCESS_TERMINATE = 0x0001                  #  Required to terminate a process using TerminateProcess.
PROCESS_VM_OPERATION = 0x0008               #  Required to perform an operation on the address space of a process = see VirtualProtectEx and WriteProcessMemory #.
PROCESS_VM_READ = 0x0010                    #  Required to read memory in a process using ReadProcessMemory.
PROCESS_VM_WRITE = 0x0020                   #  Required to write to memory in a process using WriteProcessMemory.
SYNCHRONIZE = 0x00100000                    #  Required to wait for the process to terminate using the wait functions.
PROCESS_ALL_ACCESS = PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RESET = 0x00080000
MEM_RESET_UNDO = 0x1000000
MEM_LARGE_PAGES = 0x20000000
MEM_PHYSICAL = 0x00400000
MEM_TOP_DOWN = 0x00100000

PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

EXECUTE_IMMEDIATELY = 0x00000000
CREATE_SUSPENDED = 0x00000004
STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000

# Define Win32 Structures
MEMORY_STATES = {0x1000: "MEM_COMMIT", 0x10000: "MEM_FREE", 0x2000: "MEM_RESERVE"}
MEMORY_PROTECTIONS = {0x10: "EXECUTE", 0x20: "EXECUTE_READ", 0x40: "EXECUTE_READWRITE",
                     0x80: "EXECUTE_WRITECOPY", 0x01: "NOACCESS", 0x04: "READWRITE", 0x08: "WRITECOPY", 0x02: "READONLY"}
MEMORY_TYPES = {0x1000000: "MEM_IMAGE", 0x40000: "MEM_MAPPED", 0x20000: "MEM_PRIVATE"}
 
class MEMORY_BASIC_INFORMATION32 (Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD)
        ]

class MEMORY_BASIC_INFORMATION64 (Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", DWORD),
        ("__alignment1", DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
        ("__alignment2", DWORD)
        ]

class SYSTEM_INFO(Structure):

    _fields_ = [("wProcessorArchitecture", WORD),
                ("wReserved", WORD),
                ("dwPageSize", DWORD),
                ("lpMinimumApplicationAddress", LPVOID),
                ("lpMaximumApplicationAddress", LPVOID),
                ("dwActiveProcessorMask", DWORD),
                ("dwNumberOfProcessors", DWORD),
                ("dwProcessorType", DWORD),
                ("dwAllocationGranularity", DWORD),
                ("wProcessorLevel", WORD),
                ("wProcessorRevision", WORD)]

class MEMORY_BASIC_INFORMATION:

    def __init__ (self, MBI):
        self.MBI = MBI
        self.set_attributes()

    def set_attributes(self):
        self.BaseAddress = self.MBI.BaseAddress
        self.AllocationBase = self.MBI.AllocationBase
        self.AllocationProtect = MEMORY_PROTECTIONS.get(self.MBI.AllocationProtect, self.MBI.AllocationProtect)
        self.RegionSize = self.MBI.RegionSize
        self.State = MEMORY_STATES.get(self.MBI.State, self.MBI.State)
        self.Protect = MEMORY_PROTECTIONS.get(self.MBI.Protect, self.MBI.Protect)
        self.Type = MEMORY_TYPES.get(self.MBI.Type, self.MBI.Type)
        self.ProtectBits = self.MBI.Protect

# Define Win32 APIs
OpenProcess = windll.kernel32.OpenProcess
OpenProcess.restype = HANDLE
OpenProcess.argtypes = (DWORD, BOOL, DWORD)

ReadProcessMemory = windll.kernel32.ReadProcessMemory
ReadProcessMemory.restype = BOOL
ReadProcessMemory.argtypes = (HANDLE, LPCVOID, LPVOID, DWORD, DWORD)

WriteProcessMemory = windll.kernel32.WriteProcessMemory
WriteProcessMemory.restype = BOOL
WriteProcessMemory.argtypes = (HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T)

GetLastError = windll.kernel32.GetLastError
GetLastError.restype = DWORD
GetLastError.argtypes = ()

GetProcessImageFileNameA = windll.psapi.GetProcessImageFileNameA
GetProcessImageFileNameA.restype = DWORD
GetProcessImageFileNameA.argtypes = (HANDLE, LPSTR, DWORD)

VirtualProtectEx = windll.kernel32.VirtualProtectEx
VirtualProtectEx.restype = DWORD
VirtualProtectEx.argtypes = (HANDLE, LPVOID, SIZE_T, DWORD, PDWORD)

# Win32 API implementations
def VirtualQueryEx(hProcess, lpAddress, process_is32):
    if process_is32:
        lpBuffer = MEMORY_BASIC_INFORMATION32()
    else:
        lpBuffer = MEMORY_BASIC_INFORMATION64()

    success = windll.kernel32.VirtualQueryEx(hProcess, LPVOID(lpAddress), byref(lpBuffer), sizeof(lpBuffer))
    assert success,  "VirtualQueryEx Failed.\n%s" % (WinError(GetLastError())[1])
    return MEMORY_BASIC_INFORMATION(lpBuffer)

def GetMappedFileNameA(hProcess, lpAddress):
    file_name = ctypes.create_string_buffer(512)
    file_len = windll.psapi.GetMappedFileNameA(hProcess, LPVOID(lpAddress), file_name, sizeof(file_name))

    if len(file_name) <= 0:
        print(c.RED + f"[-] Failed to get FileName!: \n\t{WinError(GetLastError())}", c.RESET)
    else:
        image_file = file_name[:file_len].decode()
        index = image_file.find("HarddiskVolume") + len("HarddiskVolumne") + 1
        return "c:\\" + image_file[index:]
        

# Custom MemoryManager
class MemoryMap:
    def __init__(self, process_id) -> None:
        self.proc_id = process_id
        self.memory = b''
        self.extracted_image = b''
    
    def get_memory_range(self):
        si = SYSTEM_INFO()
        psi = byref(si)
        windll.kernel32.GetSystemInfo(psi)
        base_address = si.lpMinimumApplicationAddress
        
        #print(f"Min Page Start: {hex(base_address)} Max Page End: {hex(si.lpMaximumApplicationAddress)}")

        return si.lpMaximumApplicationAddress

    def get_imagefile(self, hProcess):
        """
        Convert PID to ImageFile
        """
        image_name = ctypes.create_string_buffer(512)
        image_len = 0

        image_len = GetProcessImageFileNameA(hProcess, image_name, sizeof(image_name))

        if image_len > 0:
            image = image_name[:image_len].decode()
            index = image.find("HarddiskVolume") + len("HarddiskVolumne") + 1
            return "c:\\" + image[index:]
        
        return None

    def get_process_handle(self, dwProcessId, dwDesiredAccess, bInheritHandle=False):
        handle = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
        if handle is None or handle == 0:
            raise Exception(c.RED + f"Error: {GetLastError()}" + c.RESET)
        
        return handle

    def read_page(self, hProc, lpAddress):
        pageInfo = VirtualQueryEx(hProc, lpAddress, False)
        base_address = pageInfo.BaseAddress
        region_size = pageInfo.RegionSize
        next_page = base_address + region_size
        
        # Confirm we are only extracting our image
        if self.verify_image(hProc, pageInfo):
            # Save extracted image 
            self.extract_image(hProc, pageInfo)
        
        # print(c.BLUE + "[+] Next page at: ", hex(next_page))
        return next_page
    
    def scan_memory(self, pid):
        lpAddress = 0xFFFFFFFF  # If x64 -> self.get_memory_range()
        print(c.GREEN + f"[+] Scanning memory for PID: {pid}", c.RESET)
        hProc = self.get_process_handle(pid, PROCESS_ALL_ACCESS)
        address = 0x0
        while address < lpAddress:
            next_page = self.read_page(hProc, address)
            address = next_page
    
    def read_buffer(self, hProcess, lpBaseAddress, nSize):
        dwNumberOfBytesRead = ReadProcessMemory.argtypes[-1]()
        lpBuffer = ctypes.create_string_buffer(nSize)
        try:
            result = ReadProcessMemory(hProcess, LPVOID(lpBaseAddress), lpBuffer, nSize, ctypes.addressof(dwNumberOfBytesRead))
            if result is None or result == 0:
                raise Exception('Error: %s' % GetLastError())

            if dwNumberOfBytesRead.value != nSize:
                raise Exception('Read %s bytes when %s bytes should have been read' % (dwNumberOfBytesRead.value, nSize))
        except:
            error = str(WinError(GetLastError()))
            if 'completed successfully' in error:
                pass
            else:
                print(c.RED + error, c.RESET)
            
        return lpBuffer.raw
    
    def verify_image(self, hProc: HANDLE, pageInfo: MEMORY_BASIC_INFORMATION):
        our_image = self.get_imagefile(hProc)
        image_file = GetMappedFileNameA(hProc, pageInfo.BaseAddress)
        if our_image == image_file:
            print(c.BLUE + f'[+] Found memory related to our base image!\n\t Image: {our_image}\n\t BaseAddress: {hex(pageInfo.BaseAddress)}\n\t RegionSize: {pageInfo.RegionSize}', c.RESET)
            return True
        
        return False

    def extract_image(self, hProc: HANDLE, pageInfo: MEMORY_BASIC_INFORMATION):
        """
        Use ReadProcessMemory to get our buffer
        """
        
        # Get size of page to extract
        mem_mapped = self.read_buffer(hProc, pageInfo.BaseAddress, pageInfo.RegionSize)

        self.extracted_image += mem_mapped

    
if __name__ == "__main__":
    m = MemoryMap(4660)

    m.scan_memory(4660)

    hexdump(m.extracted_image[:100])
    print(len(m.extracted_image))

    with open('extracted_test.bin', 'wb') as f:
        f.write(m.extracted_image)

