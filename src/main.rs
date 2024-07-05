extern crate winapi;
use ansi_term::Colour::{Blue, Cyan, Green, Red, Yellow};
use ansi_term::Style;
use std::ffi::CStr;
use std::io::{self, Write};
use std::mem;
use std::os::raw::c_char;
use std::ptr;
use winapi::shared::minwindef::DWORD;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
use winapi::um::winnt::{HANDLE, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS, PROCESS_ALL_ACCESS};

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
                    let exe_name = CStr::from_ptr(process_entry.szExeFile.as_ptr() as *const c_char)
                        .to_string_lossy()
                        .into_owned();
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

fn open_process(pid: u32) -> Result<HANDLE, String> {
    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if handle.is_null() {
            Err(format!("Failed to open process. Error code: {}", winapi::um::errhandlingapi::GetLastError()))
        } else {
            Ok(handle)
        }
    }
}

fn read_memory(process_handle: HANDLE, address: usize, buffer: &mut [u8]) -> bool {
    unsafe {
        let mut bytes_read: usize = 0;
        ReadProcessMemory(
            process_handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            buffer.len(),
            &mut bytes_read,
        ) != 0 && bytes_read == buffer.len()
    }
}

#[derive(Debug, Clone, Copy)]
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
        let mut mem_info = MEMORY_BASIC_INFORMATION {
            BaseAddress: ptr::null_mut(),
            AllocationBase: ptr::null_mut(),
            AllocationProtect: 0,
            RegionSize: 0,
            State: 0,
            Protect: 0,
            Type: 0,
        };
        let result = unsafe {
            VirtualQueryEx(
                process_handle,
                address as *const _,
                &mut mem_info,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break;
        }

        if mem_info.State == MEM_COMMIT
            && (mem_info.Protect & PAGE_GUARD) == 0
            && mem_info.Protect != PAGE_NOACCESS
            && (mem_info.Protect & winapi::um::winnt::PAGE_READONLY != 0
            || mem_info.Protect & winapi::um::winnt::PAGE_READWRITE != 0
            || mem_info.Protect & winapi::um::winnt::PAGE_EXECUTE_READ != 0
            || mem_info.Protect & winapi::um::winnt::PAGE_EXECUTE_READWRITE != 0)
        {
            let mut current_address = mem_info.BaseAddress as usize;
            let end_address = current_address + mem_info.RegionSize;

            while current_address < end_address {
                let bytes_to_read = (end_address - current_address).min(buffer.len());
                buffer.resize(bytes_to_read, 0);

                if read_memory(process_handle, current_address, &mut buffer) {
                    for i in 0..=buffer.len().saturating_sub(value_size) {
                        let slice = &buffer[i..i + value_size];
                        match value_type {
                            ValueType::Byte | ValueType::Word | ValueType::Dword | ValueType::Qword => {
                                if slice == value {
                                    addresses.push(current_address + i);
                                    println!(
                                        "Found match at address 0x{:X} for value {:?}",
                                        current_address + i,
                                        value
                                    );
                                }
                            }
                            ValueType::Float => {
                                if slice.len() == 4 {
                                    let scanned_value = unsafe { *(slice.as_ptr() as *const f32) };
                                    let target_value = unsafe { *(value.as_ptr() as *const f32) };
                                    if (scanned_value - target_value).abs() < 0.0001 {
                                        addresses.push(current_address + i);
                                        println!(
                                            "Found approximate match at address 0x{:X} for value {:.6}",
                                            current_address + i,
                                            scanned_value
                                        );
                                    }
                                }
                            }
                            ValueType::Double => {
                                if slice.len() == 8 {
                                    let scanned_value = unsafe { *(slice.as_ptr() as *const f64) };
                                    let target_value = unsafe { *(value.as_ptr() as *const f64) };
                                    if (scanned_value - target_value).abs() < 0.000001 {
                                        addresses.push(current_address + i);
                                        println!(
                                            "Found approximate match at address 0x{:X} for value {:.8}",
                                            current_address + i,
                                            scanned_value
                                        );
                                    }
                                }
                            }
                            ValueType::String => {
                                if slice.windows(value.len()).any(|window| window == value) {
                                    addresses.push(current_address + i);
                                    println!(
                                        "Found UTF-8 match at address 0x{:X} for value {:?}",
                                        current_address + i,
                                        value
                                    );
                                }

                                // UTF-16 search
                                let utf16_value: Vec<u16> = String::from_utf8_lossy(value)
                                    .encode_utf16()
                                    .collect();
                                let utf16_bytes: Vec<u8> = utf16_value
                                    .iter()
                                    .flat_map(|&b| b.to_ne_bytes())
                                    .collect();
                                if slice.windows(utf16_bytes.len()).any(|window| window == utf16_bytes) {
                                    addresses.push(current_address + i);
                                    println!(
                                        "Found UTF-16 match at address 0x{:X} for value {:?}",
                                        current_address + i,
                                        String::from_utf16_lossy(&utf16_value)
                                    );
                                }
                            }
                        }
                    }
                }
                current_address += bytes_to_read;
            }
        }
        address = (mem_info.BaseAddress as usize) + mem_info.RegionSize;
    }

    addresses
}

fn get_user_input<T: std::str::FromStr>(prompt: &str) -> Result<T, String> {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    input.trim().parse().map_err(|_| "Invalid input".to_string())
}

fn main() {
    let processes = enumerate_processes();
    println!("{}", Style::new().bold().fg(Blue).paint("Processes:"));
    for (pid, name) in &processes {
        println!("Process ID: {}, Process Name: {}", Yellow.paint(pid.to_string()), Cyan.paint(name));
    }

    let pid: u32 = match get_user_input("Enter the process ID to scan: ") {
        Ok(id) => id,
        Err(e) => {
            println!("{}", Red.paint(format!("Error: {}", e)));
            return;
        }
    };

    match open_process(pid) {
        Ok(process_handle) => {
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

                let choice: u32 = match get_user_input("Enter your choice (1-7): ") {
                    Ok(c) => c,
                    Err(e) => {
                        println!("{}", Red.paint(format!("Error: {}", e)));
                        continue;
                    }
                };

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
                let value = match value_type {
                    ValueType::String => input.trim().as_bytes().to_vec(),
                    ValueType::Float => {
                        match input.trim().parse::<f32>() {
                            Ok(parsed_value) => parsed_value.to_ne_bytes().to_vec(),
                            Err(_) => {
                                println!("{}", Red.paint("Invalid float value. Please try again."));
                                continue;
                            }
                        }
                    },
                    ValueType::Double => {
                        match input.trim().parse::<f64>() {
                            Ok(parsed_value) => parsed_value.to_ne_bytes().to_vec(),
                            Err(_) => {
                                println!("{}", Red.paint("Invalid double value. Please try again."));
                                continue;
                            }
                        }
                    },
                    ValueType::Byte => {
                        match input.trim().parse::<u8>() {
                            Ok(parsed_value) => vec![parsed_value],
                            Err(_) => {
                                println!("{}", Red.paint("Invalid byte value. Please enter a number between 0 and 255."));
                                continue;
                            }
                        }
                    },
                    ValueType::Word => {
                        match input.trim().parse::<u16>() {
                            Ok(parsed_value) => parsed_value.to_ne_bytes().to_vec(),
                            Err(_) => {
                                println!("{}", Red.paint("Invalid word value. Please enter a number between 0 and 65535."));
                                continue;
                            }
                        }
                    },
                    ValueType::Dword => {
                        match input.trim().parse::<u32>() {
                            Ok(parsed_value) => parsed_value.to_ne_bytes().to_vec(),
                            Err(_) => {
                                println!("{}", Red.paint("Invalid dword value. Please enter a number between 0 and 4294967295."));
                                continue;
                            }
                        }
                    },
                    ValueType::Qword => {
                        match input.trim().parse::<u64>() {
                            Ok(parsed_value) => parsed_value.to_ne_bytes().to_vec(),
                            Err(_) => {
                                println!("{}", Red.paint("Invalid qword value. Please enter a number."));
                                continue;
                            }
                        }
                    },
                };

                let addresses = scan_memory(process_handle, value_type, &value);
                println!("Found {} matches:", Yellow.paint(addresses.len().to_string()));
                for address in &addresses {
                    println!("Address: {}", Cyan.paint(format!("0x{:X}", address)));
                }

                let continue_scan: String = match get_user_input("Do you want to scan again? (y/n): ") {
                    Ok(answer) => answer,
                    Err(e) => {
                        println!("{}", Red.paint(format!("Error: {}", e)));
                        break;
                    }
                };

                if continue_scan.to_lowercase() != "y" {
                    break;
                }
            }

            unsafe {
                winapi::um::handleapi::CloseHandle(process_handle);
            }
        }
        Err(e) => {
            println!("{}", Red.paint(format!("Failed to open process: {}", e)));
        }
    }
}