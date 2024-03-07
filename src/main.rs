extern crate winapi;

use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{HANDLE, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::mem;
use std::io::{self, Write};
use ansi_term::Colour::{Blue, Cyan, Green, Red, Yellow};
use ansi_term::Style;

fn enumerate_processes() -> Vec<(u32, String)> {
    let mut processes = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot != INVALID_HANDLE_VALUE {
            let mut process_entry = PROCESSENTRY32 {
                dwSize: mem::size_of::<PROCESSENTRY32>() as u32,
                cntUsage: 0,
                th32ProcessID: 0,
                th32DefaultHeapID: 0,
                th32ModuleID: 0,
                cntThreads: 0,
                th32ParentProcessID: 0,
                pcPriClassBase: 0,
                dwFlags: 0,
                szExeFile: [0; 260],
            };

            if Process32First(snapshot, &mut process_entry) != 0 {
                loop {
                    let exe_name = CStr::from_ptr(process_entry.szExeFile.as_ptr() as *const c_char).to_string_lossy().into_owned();
                    processes.push((process_entry.th32ProcessID, exe_name));

                    if Process32Next(snapshot, &mut process_entry) == 0 {
                        break;
                    }
                }
            }
            winapi::um::handleapi::CloseHandle(snapshot);
        }
    }
    processes
}

fn open_process(pid: u32) -> Option<HANDLE> {
    unsafe {
        let handle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, pid);
        if handle.is_null() {
            None
        } else {
            Some(handle)
        }
    }
}

fn read_memory(process_handle: HANDLE, address: usize, buffer: &mut [u8]) -> bool {
    unsafe {
        ReadProcessMemory(process_handle, address as *const _, buffer.as_mut_ptr() as *mut _, buffer.len(), std::ptr::null_mut()) != 0
    }
}

fn write_memory(process_handle: HANDLE, address: usize, buffer: &[u8]) -> bool {
    unsafe {
        WriteProcessMemory(process_handle, address as *mut _, buffer.as_ptr() as *const _, buffer.len(), std::ptr::null_mut()) != 0
    }
}

enum ValueType {
    Byte,
    Word,
    Dword,
    Qword,
    Float,
    Double,
    String,
}

fn scan_memory(process_handle: HANDLE, value_type: ValueType, value: &[u8]) -> Vec<usize> {
    let mut addresses = Vec::new();
    let mut buffer = vec![0u8; 4096];
    let mut address: usize = 0;
    println!("Searching for value: {:?}", value);

    let value_size = match value_type {
        ValueType::Byte => 1,
        ValueType::Word => 2,
        ValueType::Dword => 4,
        ValueType::Qword => 8,
        ValueType::Float => 4,
        ValueType::Double => 8,
        ValueType::String => value.len(),
    };

    loop {
        let mut bytes_read = 0;
        let mut mem_info = winapi::um::winnt::MEMORY_BASIC_INFORMATION {
            BaseAddress: std::ptr::null_mut(),
            AllocationBase: std::ptr::null_mut(),
            AllocationProtect: 0,
            RegionSize: 0,
            State: 0,
            Protect: 0,
            Type: 0,
        };
        let result = unsafe {
            winapi::um::memoryapi::VirtualQueryEx(
                process_handle,
                address as *const _,
                &mut mem_info,
                std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break;
        }

        if mem_info.State == winapi::um::winnt::MEM_COMMIT
            && (mem_info.Protect & winapi::um::winnt::PAGE_GUARD) == 0
            && mem_info.Protect != winapi::um::winnt::PAGE_NOACCESS
        {
            if read_memory(process_handle, address, &mut buffer) {
                unsafe {
                    ReadProcessMemory(
                        process_handle,
                        address as *const _,
                        buffer.as_mut_ptr() as *mut _,
                        buffer.len(),
                        &mut bytes_read,
                    );
                }
                // println!("Read {} bytes at address 0x{:X}", bytes_read, address);

                if bytes_read == 0 {
                    break;
                }

                for i in 0..=bytes_read.saturating_sub(value_size) {
                    let slice = &buffer[i..i + value_size];
                    if slice == value {
                        addresses.push(address + i);
                        println!(
                            "Found match at address 0x{:X} for value {:?}",
                            address + i,
                            value
                        );
                    }
                }
            }
        }
        address = (mem_info.BaseAddress as usize) + mem_info.RegionSize;
    }

    addresses
}

fn main() {
    let processes = enumerate_processes();
    println!("{}", Style::new().bold().fg(Blue).paint("Processes:"));
    for (pid, name) in &processes {
        println!("Process ID: {}, Process Name: {}", Yellow.paint(pid.to_string()), Cyan.paint(name));
    }

    print!("Enter the process ID to scan: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let pid = input.trim().parse::<u32>().unwrap();

    if let Some(process_handle) = open_process(pid) {
        println!("{}", Green.paint("Process opened successfully."));

        loop {
            println!("\n{}", Style::new().bold().fg(Blue).paint("Select the value type to scan for:"));
            println!("1. Byte");
            println!("2. Word (2 bytes)");
            println!("3. Dword (4 bytes)");
            println!("4. Qword (8 bytes)");
            println!("5. Float");
            println!("6. Double");
            println!("7. String");

            print!("Enter your choice (1-7): ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            let choice = input.trim().parse::<u32>().unwrap();

            let value_type = match choice {
                1 => ValueType::Byte,
                2 => ValueType::Word,
                3 => ValueType::Dword,
                4 => ValueType::Qword,
                5 => ValueType::Float,
                6 => ValueType::Double,
                7 => ValueType::String,
                _ => {
                    println!("{}", Red.paint("Invalid choice. Please try again."));
                    continue;
                }
            };

            print!("Enter the value to scan for: ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            let value = input.trim().as_bytes().to_vec();

            let addresses = scan_memory(process_handle, value_type, &value);
            println!("Found {} matches:", Yellow.paint(addresses.len().to_string()));
            for address in &addresses {
                println!("Address: {}", Cyan.paint(format!("0x{:X}", address)));
            }

            print!("Do you want to scan again? (y/n): ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            if input.trim().to_lowercase() != "y" {
                break;
            }
        }

        unsafe {
            winapi::um::handleapi::CloseHandle(process_handle);
        }
    } else {
        println!("{}", Red.paint("Failed to open process."));
    }
}