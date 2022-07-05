use core::ffi::c_void;
use std::ffi::{CStr, CString};
use windows::core::PCSTR;
use windows::Win32::Foundation::*;
use windows::Win32::Security::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Services::*;
use windows::Win32::System::SystemServices::*;
use windows::Win32::System::Threading::*;

const SMALLEST_PE_SIZE64: usize = 268;

struct ScHandle {
    h: SC_HANDLE,
}

impl ScHandle {
    fn from_raw_handle(raw: SC_HANDLE) -> ScHandle {
        ScHandle { h: raw }
    }

    fn raw(&self) -> &SC_HANDLE {
        &self.h
    }

    fn reset(&mut self, raw: SC_HANDLE) {
        if !self.h.is_invalid() {
            unsafe { CloseServiceHandle(self.h) };
        }

        self.h = raw;
    }
}

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.h.is_invalid() {
            unsafe { CloseServiceHandle(self.h) };
        }
    }
}

pub struct PE {
    pub name: String,
    pub path: String,
    pub size: usize,
    image_base: *mut c_void,

    dos_header: IMAGE_DOS_HEADER,
    nt_headers: IMAGE_NT_HEADERS64,
    file_header: IMAGE_FILE_HEADER,
    optional_header: IMAGE_OPTIONAL_HEADER64,
    section_headers: *const IMAGE_SECTION_HEADER,

    export_address_table: *const IMAGE_EXPORT_DIRECTORY,
    import_address_table: *const IMAGE_IMPORT_DESCRIPTOR,

    exported_functions: Vec<String>,
    imported_functions: Vec<(String, String)>, // library_name, function_name

    provided_driver_name: String,
    read_physical_mem: fn(*const c_void, usize) -> Vec<u8>, // r
    write_physical_mem: fn(*mut c_void, &Vec<u8>, usize),   // w
}

pub trait Driver {
    fn enable_driver_load_privilege() -> Option<()> {
        let mut tp = TOKEN_PRIVILEGES::default();
        let mut luid = LUID::default();
        let mut token = HANDLE::default();

        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) }
            == false
        {
            panic!("Could not open process token");
        }

        let priv_name = CString::new(SE_LOAD_DRIVER_NAME).unwrap();
        if unsafe {
            LookupPrivilegeValueA(
                PCSTR::default(),
                PCSTR(priv_name.as_ptr() as *const _),
                &mut luid as *mut LUID,
            )
        } == false
        {
            panic!("Could not find LUID of the driver load privilege");
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if unsafe {
            AdjustTokenPrivileges(
                token,
                false,
                &mut tp,
                core::mem::size_of::<TOKEN_PRIVILEGES>().try_into().unwrap(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == false
        {
            panic!("Could not adjust token's privileges");
        }

        unsafe { CloseHandle(token) };

        Some(())
    }

    fn load(&mut self, driver_name: &str) -> Option<()>;
    fn unload(&mut self) -> Option<()>;
}

impl PE {
    pub fn from_disk(path: &String) -> Option<Self> {
        let mut image_bytes = std::fs::read(path).unwrap();
        let pre_dos_header = unsafe { image_bytes.as_ptr().cast::<IMAGE_DOS_HEADER>().read() };

        if u32::from(pre_dos_header.e_magic) != IMAGE_DOS_SIGNATURE {
            panic!("image signature corrupt");
        }

        let pre_nt_headers = unsafe {
            image_bytes
                .as_ptr()
                .offset(pre_dos_header.e_lfanew.try_into().unwrap())
                .cast::<IMAGE_NT_HEADERS64>()
                .read()
        };
        if pre_nt_headers.Signature != IMAGE_NT_SIGNATURE {
            panic!("image signature corrupt");
        }

        let image_size = pre_nt_headers.OptionalHeader.SizeOfImage as usize;
        // the 16 bytes at the start are for potential shellcode space
        // (for the shellcode conversion function)
        let image_base = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                (16 + image_size).try_into().unwrap(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
            .add(16)
        };
        let headers_size = pre_nt_headers.OptionalHeader.SizeOfHeaders;
        // copying image headers to allocated virtual memory
        unsafe {
            std::ptr::copy_nonoverlapping(
                image_bytes.as_ptr(),
                image_base as *mut u8,
                headers_size.try_into().unwrap(),
            )
        };

        let section_count = pre_nt_headers.FileHeader.NumberOfSections;
        let _section_headers = unsafe {
            std::slice::from_raw_parts(
                image_bytes
                    .as_ptr()
                    .offset(pre_dos_header.e_lfanew.try_into().unwrap())
                    .offset(
                        core::mem::size_of::<IMAGE_NT_HEADERS64>()
                            .try_into()
                            .unwrap(),
                    )
                    .cast::<IMAGE_SECTION_HEADER>(),
                section_count.into(),
            )
        };

        // copy all of the image sections to allocated memory
        for i in 0..section_count {
            let current_section_header = _section_headers[usize::from(i)];

            unsafe {
                std::ptr::copy(
                    image_bytes
                        .as_ptr()
                        .offset(current_section_header.PointerToRawData.try_into().unwrap()),
                    image_base.offset(current_section_header.VirtualAddress.try_into().unwrap())
                        as *mut u8,
                    current_section_header.SizeOfRawData.try_into().unwrap(),
                );
            };
        }

        image_bytes.clear();

        let dos_header = unsafe { image_base.cast::<IMAGE_DOS_HEADER>().read() };
        if u32::from(dos_header.e_magic) != IMAGE_DOS_SIGNATURE {
            panic!("image signature corrupt");
        }

        let nt_headers = unsafe {
            image_base
                .offset(dos_header.e_lfanew.try_into().unwrap())
                .cast::<IMAGE_NT_HEADERS64>()
                .read()
        };
        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            panic!("image signature corrupt");
        }

        let file_header = nt_headers.FileHeader;
        let optional_header = nt_headers.OptionalHeader;
        let section_headers = unsafe {
            image_base
                .offset(pre_dos_header.e_lfanew.try_into().unwrap())
                .offset(
                    core::mem::size_of::<IMAGE_NT_HEADERS64>()
                        .try_into()
                        .unwrap(),
                )
                .cast::<IMAGE_SECTION_HEADER>()
        };

        let export_address_table = unsafe {
            image_base
                .offset(
                    optional_header.DataDirectory[0]
                        .VirtualAddress
                        .try_into()
                        .unwrap(),
                )
                .cast::<IMAGE_EXPORT_DIRECTORY>()
        };
        let import_address_table = unsafe {
            image_base
                .offset(
                    optional_header.DataDirectory[1]
                        .VirtualAddress
                        .try_into()
                        .unwrap(),
                )
                .cast::<IMAGE_IMPORT_DESCRIPTOR>()
        };

        let image_name = unsafe {
            match (*export_address_table).Name {
                // in case the image has a hollow EAT
                0xffff => path.rsplit("\\").collect::<Vec<&str>>()[0].to_string(),
                0 => path.rsplit("\\").collect::<Vec<&str>>()[0].to_string(),
                _ => CStr::from_ptr(
                    image_base.offset((*export_address_table).Name.try_into().unwrap())
                        as *const i8,
                )
                .to_str()
                .unwrap()
                .to_string(),
            }
        };

        unsafe { PE::perform_relocations(image_base, optional_header) };

        Some(PE {
            name: image_name,
            path: path.clone(),
            size: image_size,
            image_base: image_base,

            dos_header: dos_header,
            nt_headers: nt_headers,
            file_header: file_header,
            optional_header: optional_header,
            section_headers: section_headers,

            export_address_table: export_address_table,
            import_address_table: import_address_table,
            // todo: a real function to init those
            exported_functions: vec!["".to_string()],
            imported_functions: vec![("".to_string(), "".to_string())],

            provided_driver_name: "".to_string(),
            read_physical_mem: |dst, size| -> Vec<u8> { vec![] },
            write_physical_mem: |dst, src, size| {},
        })
    }

    // perform necessary reloactions for absolute addresses
    unsafe fn perform_relocations(
        image_base: *mut c_void,
        optional_header: IMAGE_OPTIONAL_HEADER64,
    ) {
        // acquire delta between actual base addr and wanted base addr
        let delta = image_base.sub(optional_header.ImageBase as usize);
        if !delta.is_null() {
            let mut base_relocation = image_base
                .add(
                    optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize]
                        .VirtualAddress as usize,
                )
                .cast::<IMAGE_BASE_RELOCATION>();

            // make sure we have control over base_relocation before
            // dereferencing
            let mut mem_permissions = MEMORY_BASIC_INFORMATION::default();
            VirtualQuery(
                base_relocation.cast::<c_void>(),
                &mut mem_permissions,
                (*base_relocation).SizeOfBlock.try_into().unwrap(),
            );

            while mem_permissions.Protect != PAGE_NOACCESS
                && mem_permissions.Protect != PAGE_EXECUTE
            {
                // no addresses to fix at this block
                if (*base_relocation).SizeOfBlock
                    == core::mem::size_of::<IMAGE_BASE_RELOCATION>()
                        .try_into()
                        .unwrap()
                {
                    base_relocation = base_relocation.add((*base_relocation).SizeOfBlock as usize);
                    continue;
                }

                // amount of addresses whice need relocation
                let reloc_count = ((*base_relocation).SizeOfBlock as isize
                    - (core::mem::size_of::<IMAGE_BASE_RELOCATION>() as isize))
                    / (core::mem::size_of::<i16>() as isize);
                // array of offsets from base of page
                let reloc_offsets = std::slice::from_raw_parts(
                    base_relocation
                        .add(core::mem::size_of::<IMAGE_BASE_RELOCATION>())
                        .cast::<u16>(),
                    reloc_count as usize,
                );

                for reloc_index in 0..reloc_count {
                    *image_base
                        .add((*base_relocation).VirtualAddress.try_into().unwrap())
                        .add((reloc_offsets[reloc_index as usize] & 0xfff).into())
                        .cast::<u64>() += delta as u64;
                }

                // if size of block is 0, there's no subsequent block
                if (*base_relocation).SizeOfBlock == 0 {
                    break;
                }
                VirtualQuery(
                    base_relocation
                        .add((*base_relocation).SizeOfBlock as usize)
                        .cast::<c_void>(),
                    &mut mem_permissions,
                    (*base_relocation).SizeOfBlock.try_into().unwrap(),
                );
                base_relocation = base_relocation.add((*base_relocation).SizeOfBlock as usize);
            }
        }
    }

    /// returns the virtual address for the program's entry point
    pub fn entry_point(&self) -> *const c_void {
        unsafe {
            self.image_base
                .add(self.optional_header.AddressOfEntryPoint as usize)
        }
    }

    /// returns the relative virtual address for the program's entry point
    pub fn entry_point_rel(&self) -> u32 {
        self.optional_header.AddressOfEntryPoint
    }
    /// determines whether the image is 64 bit or not
    pub fn is_64bit(&self) -> bool {
        if self.optional_header.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return true;
        }
        false
    }

    /// returns the architecture which the PE was compiled for
    pub fn arch(&self) -> IMAGE_FILE_MACHINE {
        self.file_header.Machine
    }

    // NOTE: can only work with completely PIC, dependency-free EXEs
    // with a custom entry point
    /// converts the PE to runnable(ish) 64-bit shellcode with constraints
    pub fn convert_to_shellcode_64(&self) -> &[u8] {
        let mut shellcode: [u8; 16] = [0; 16];
        let offset_to_entry_point = 18 + self.entry_point_rel();

        // lea rax, [rip]
        shellcode[0] = 0x48;
        shellcode[1] = 0x8d;
        shellcode[2] = 0x05;
        shellcode[3] = 0x00;
        shellcode[4] = 0x00;
        shellcode[5] = 0x00;
        shellcode[6] = 0x00;
        // add rax, offset_to_entry_point_from_rip
        shellcode[7] = 0x48;
        shellcode[8] = 0x05;
        // writing offset_to_entry_point_from_rip into buffer
        unsafe {
            std::ptr::write(
                (&mut shellcode[9] as *mut u8).cast::<u32>(),
                offset_to_entry_point,
            )
        };

        // call rax (calling custom entry point of import-independent PE)
        shellcode[13] = 0xff;
        shellcode[14] = 0xd0;

        // copy shellcode to pre-allocated space before image_base
        unsafe {
            std::ptr::copy(
                shellcode.as_ptr(),
                self.image_base.sub(16).cast::<u8>(),
                shellcode.len(),
            )
        };

        unsafe { std::slice::from_raw_parts(self.image_base.sub(16).cast::<u8>(), self.size + 16) }
    }
}

impl Drop for PE {
    fn drop(&mut self) {
        let mut mem_permissions = MEMORY_BASIC_INFORMATION::default();
        unsafe { VirtualQuery(self.image_base, &mut mem_permissions, SMALLEST_PE_SIZE64) };

        // if image_base is valid and wasn't freed prior
        if !self.image_base.is_null() && mem_permissions.Protect != PAGE_NOACCESS {
            unsafe { VirtualFree(self.image_base, 0, MEM_RELEASE) };
        }
        // if driver has been loaded
        if self.provided_driver_name != "".to_string() {
            self.unload();
        }
    }
}

impl Driver for PE {
    fn load(&mut self, driver_name: &str) -> Option<()> {
        if self.path.is_empty() {
            panic!("Driver path is empty");
        }

        if let None = Self::enable_driver_load_privilege() {
            panic!("Could not enable driver load privilege");
        }

        self.provided_driver_name = driver_name.to_string();

        let service_mgr = unsafe {
            ScHandle::from_raw_handle(
                OpenSCManagerA(
                    PCSTR(std::ptr::null()),
                    PCSTR(std::ptr::null()),
                    SC_MANAGER_ALL_ACCESS,
                )
                .unwrap(),
            )
        };
        if service_mgr.raw().is_invalid() {
            panic!("Could not open handle to service manager");
        }

        let mut service_ddk = unsafe {
            ScHandle::from_raw_handle(
                CreateServiceA(
                    service_mgr.raw(),
                    PCSTR(self.provided_driver_name.as_str().as_ptr()),
                    PCSTR(self.provided_driver_name.as_str().as_ptr()),
                    SERVICE_ALL_ACCESS,
                    SERVICE_KERNEL_DRIVER,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_IGNORE,
                    PCSTR(self.path.as_str().as_ptr()),
                    PCSTR(std::ptr::null()),
                    std::ptr::null_mut(),
                    PCSTR(std::ptr::null()),
                    PCSTR(std::ptr::null()),
                    PCSTR(std::ptr::null()),
                )
                .unwrap(),
            )
        };
        if service_ddk.raw().is_invalid() {
            panic!("Could not create service for the driver");
        }

        service_ddk.reset(unsafe {
            OpenServiceA(
                service_mgr.raw(),
                PCSTR(self.provided_driver_name.as_str().as_ptr()),
                SERVICE_ALL_ACCESS,
            )
            .unwrap()
        });
        if service_ddk.raw().is_invalid() {
            panic!("Could not open handle to create service");
        }

        let started = unsafe { StartServiceA(service_ddk.raw(), &[]) };
        if !started.as_bool() {
            panic!("Could not start created service");
        }

        Some(())
    }

    fn unload(&mut self) -> Option<()> {
        let mut sstatus = SERVICE_STATUS::default();

        if self.provided_driver_name.is_empty() {
            panic!("Driver hasn't been loaded");
        }

        let service_mgr = ScHandle::from_raw_handle(unsafe {
            OpenSCManagerA(
                PCSTR(std::ptr::null()),
                PCSTR(std::ptr::null()),
                SC_MANAGER_ALL_ACCESS,
            )
            .unwrap()
        });

        if service_mgr.raw().is_invalid() {
            panic!("Couldn't open handle to service manager");
        }

        let service = ScHandle::from_raw_handle(unsafe {
            OpenServiceA(
                service_mgr.raw(),
                PCSTR(self.provided_driver_name.as_str().as_ptr()),
                SERVICE_ALL_ACCESS,
            )
            .unwrap()
        });
        if service.raw().is_invalid() {
            panic!("Couldn't open handle to created service");
        }

        let mut success =
            unsafe { ControlService(service.raw(), SERVICE_CONTROL_STOP, &mut sstatus) };
        if !success.as_bool() {
            panic!("Failed to unload driver");
        }

        success = unsafe { DeleteService(service.raw()) };
        if !success.as_bool() {
            panic!("Failed to delete service");
        }

        self.provided_driver_name = "".to_string();
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use crate::Driver;
    use crate::PE;
    use std::arch::asm;
    //use std::fs;
    #[test]
    fn image_name_matches() {
        let nlmproxy = PE::from_disk(&"C:\\Windows\\system32\\nlmproxy.dll".to_string()).unwrap();
        assert_eq!(nlmproxy.name, "nlmproxy.dll".to_string());
    }

    #[test]
    fn image_64bit_check_success() {
        let nlmproxy = PE::from_disk(&"C:\\Windows\\system32\\nlmproxy.dll".to_string()).unwrap();
        let drt = PE::from_disk(&"C:\\Windows\\SysWOW64\\drt.dll".to_string()).unwrap();
        assert!(nlmproxy.is_64bit() && !drt.is_64bit());
    }

    // a different method is used for getting the image name from an EXE,
    // since it has a hollow EAT
    #[test]
    fn name_from_exe_works() {
        let notepad = PE::from_disk(&"C:\\Windows\\system32\\notepad.exe".to_string()).unwrap();
        assert_eq!(notepad.name, "notepad.exe".to_string());
    }
}
