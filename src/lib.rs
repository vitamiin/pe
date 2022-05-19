use core::ffi::c_void;
use std::ffi::{CString, CStr};
use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Security::*;
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_FILE_HEADER, IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64, IMAGE_SECTION_HEADER,
};
use windows::Win32::System::Memory::*;
use windows::Win32::System::Services::*;
use windows::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_SIGNATURE, SE_LOAD_DRIVER_NAME,
};
use windows::Win32::System::Threading::*;

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
}

pub trait Driver {
    fn enable_driver_load_privilege() -> Result<(), &'static str> {
        let mut tp = TOKEN_PRIVILEGES::default();
        let mut luid = LUID::default();
        let mut token = HANDLE::default();

        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) }
            == false
        {
            return Err("Could not open process token");
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
            return Err("Could not find LUID of the driver load privilege.");
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
            return Err("Could not adjust token's privileges");
        }

        unsafe { CloseHandle(token) };

        Ok(())
    }

    fn load(&mut self, driver_name: String) -> Result<(), &'static str>;
    fn unload(&self) -> Result<(), &'static str>;
}

impl PE {
    pub fn from_disk(path: &String) -> Result<Self, String> {
        let mut image_bytes = std::fs::read(path).unwrap();
        let pre_dos_header = unsafe {
            core::mem::transmute::<*const u8, *const IMAGE_DOS_HEADER>(image_bytes.as_ptr()).read()
        };

        if u32::from(pre_dos_header.e_magic) != IMAGE_DOS_SIGNATURE {
            return Err("image signature corrupt".to_string());
        }

        let pre_nt_headers = unsafe {
            core::mem::transmute::<*const u8, *const IMAGE_NT_HEADERS64>(
                image_bytes
                    .as_ptr()
                    .offset(pre_dos_header.e_lfanew.try_into().unwrap()),
            )
            .read()
        };
        if pre_nt_headers.Signature != IMAGE_NT_SIGNATURE {
            return Err("image signature corrupt".to_string());
        }

        let image_size = pre_nt_headers.OptionalHeader.SizeOfImage as usize;
        let image_base = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                image_size.try_into().unwrap(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
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
                core::mem::transmute::<*const u8, *const IMAGE_SECTION_HEADER>(
                    image_bytes
                        .as_ptr()
                        .offset(pre_dos_header.e_lfanew.try_into().unwrap())
                        .offset(
                            core::mem::size_of::<IMAGE_NT_HEADERS64>()
                                .try_into()
                                .unwrap(),
                        ),
                ),
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

        let dos_header = unsafe {
            core::mem::transmute::<*const c_void, *const IMAGE_DOS_HEADER>(image_base).read()
        };
        if u32::from(dos_header.e_magic) != IMAGE_DOS_SIGNATURE {
            return Err("Image signature corrupt".to_string());
        }

        let nt_headers = unsafe {
            core::mem::transmute::<*const c_void, *const IMAGE_NT_HEADERS64>(
                image_base.offset(dos_header.e_lfanew.try_into().unwrap()),
            )
            .read()
        };
        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            return Err("Image signature corrupt".to_string());
        }

        let file_header = nt_headers.FileHeader;
        let optional_header = nt_headers.OptionalHeader;
        let section_headers = unsafe {
            core::mem::transmute::<*const c_void, *const IMAGE_SECTION_HEADER>(
                image_base
                    .offset(pre_dos_header.e_lfanew.try_into().unwrap())
                    .offset(
                        core::mem::size_of::<IMAGE_NT_HEADERS64>()
                            .try_into()
                            .unwrap(),
                    ),
            )
        };

        let export_address_table = unsafe {
            core::mem::transmute::<*const c_void, *const IMAGE_EXPORT_DIRECTORY>(
                image_base.offset(
                    optional_header.DataDirectory[0]
                        .VirtualAddress
                        .try_into()
                        .unwrap(),
                ),
            )
        };
        let import_address_table = unsafe {
            core::mem::transmute::<*const c_void, *const IMAGE_IMPORT_DESCRIPTOR>(
                image_base.offset(
                    optional_header.DataDirectory[1]
                        .VirtualAddress
                        .try_into()
                        .unwrap(),
                ),
            )
        };

        let image_name = unsafe {
            match (*export_address_table).Name {
                // in case the image has a hollow EAT
                0xffff => path.rsplit("\\").collect::<Vec<&str>>()[0].to_string(),
                _ => CStr::from_ptr(
                    image_base.offset((*export_address_table).Name.try_into().unwrap())
                        as *const i8,
                )
                .to_str()
                .unwrap()
                .to_string(),
            }
        };

        Ok(PE {
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
        })
    }
}

impl Drop for PE {
    fn drop(&mut self) {
        if !self.image_base.is_null() {
            unsafe { VirtualFree(self.image_base, 0, MEM_RELEASE) };
        }

        if self.provided_driver_name != "".to_string() {
            self.unload();
        }
    }
}

impl Driver for PE {
    fn load(&mut self, driver_name: String) -> Result<(), &'static str> {
        if self.path.is_empty() {
            return Err("Driver path is empty");
        }

        if let Err(e) = Self::enable_driver_load_privilege() {
            return Err(e);
        }

        self.provided_driver_name = driver_name;

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
            return Err("Could not open handle to service manager");
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
            return Err("Could not create service for the driver");
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
            return Err("Could not open handle to created service");
        }

        let started = unsafe { StartServiceA(service_ddk.raw(), &[]) };
        if !started.as_bool() {
            return Err("Could not start created service");
        }

        Ok(())
    }

    fn unload(&self) -> Result<(), &'static str> {
        let mut sstatus = SERVICE_STATUS::default();

        if self.provided_driver_name.is_empty() {
            return Err("Driver hasn't been loaded");
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
            return Err("Couldn't open handle to service manager");
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
            return Err("Couldn't open handle to created service");
        }

        let mut success =
            unsafe { ControlService(service.raw(), SERVICE_CONTROL_STOP, &mut sstatus) };
        if !success.as_bool() {
            return Err("Failed to unload driver");
        }

        success = unsafe { DeleteService(service.raw()) };
        if !success.as_bool() {
            return Err("Failed to delete service");
        }

        Ok(())
    }
}

fn main(){
    let mut driver = PE::from_disk(&"C:\\Users\\cybea\\source\\repos\\MyDriver1\\x64\\Debug".to_string()).unwrap();
    driver.load("MyDriver2".to_string());
    driver.unload();

    assert_eq!(1, 1);
}

#[cfg(test)]
mod tests {
    use crate::PE;
    use crate::Driver;
    //use std::fs;

    #[test]
    fn image_name_matches() {
        let nlmproxy = PE::from_disk(&"C:\\Windows\\system32\\nlmproxy.dll".to_string()).unwrap();
        assert_eq!(nlmproxy.name, "nlmproxy.dll".to_string());
    }

    // a different method is used for getting the image name from an EXE,
    // since it has a hollow EAT
    #[test]
    fn name_from_exe_works() {
        let notepad = PE::from_disk(&"C:\\Windows\\system32\\notepad.exe".to_string()).unwrap();
        assert_eq!(notepad.name, "notepad.exe".to_string());
    }

    #[test]
    fn driver_works () {
        let mut driver = PE::from_disk(&"C:\\Users\\cybea\\source\\repos\\MyDriver1\\x64\\Debug\\MyDriver1.sys".to_string()).unwrap();
        if let Err(e) = driver.load("MyDriver2".to_string()){
            panic!("{}", e);
        }

        assert_eq!(driver.provided_driver_name, "MyDriver2".to_string());
    }
    /* note: image size on disk != image size in memory.
    #[test]
    fn image_size_correct() {
        let notepad = PE::from_disk(&"C:\\Windows\\system32\\notepad.exe".to_string()).unwrap();
        assert_eq!(fs::metadata("C:\\Windows\\system32\\notepad.exe").unwrap().len(), notepad.image_size as u64);
    }
    */
}
