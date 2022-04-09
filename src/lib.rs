use core::ffi::c_void;
use std::ffi::CStr;
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_FILE_HEADER, IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64, IMAGE_SECTION_HEADER,
};
use windows::Win32::System::Memory::*;
use windows::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_SIGNATURE,
};

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
}

impl PE {
    pub fn from_disk(path: &String) -> Result<Self, String> {
        let mut image_bytes = std::fs::read(path).unwrap();
        let pre_dos_header: IMAGE_DOS_HEADER =
            unsafe { (image_bytes.as_ptr() as *const IMAGE_DOS_HEADER).read() };

        if u32::from(pre_dos_header.e_magic) != IMAGE_DOS_SIGNATURE {
            return Err("image signature corrupt".to_string());
        }

        let pre_nt_headers: IMAGE_NT_HEADERS64 = unsafe {
            (image_bytes
                .as_ptr()
                .offset(pre_dos_header.e_lfanew.try_into().unwrap())
                as *const IMAGE_NT_HEADERS64)
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
        let _section_headers: &[IMAGE_SECTION_HEADER] = unsafe {
            std::slice::from_raw_parts(
                image_bytes
                    .as_ptr()
                    .offset(pre_dos_header.e_lfanew.try_into().unwrap())
                    .offset(
                        core::mem::size_of::<IMAGE_NT_HEADERS64>()
                            .try_into()
                            .unwrap(),
                    ) as *const IMAGE_SECTION_HEADER,
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

        let dos_header = unsafe { (image_base as *const IMAGE_DOS_HEADER).read() };
        if u32::from(dos_header.e_magic) != IMAGE_DOS_SIGNATURE {
            return Err("Image signature corrupt".to_string());
        }

        let nt_headers = unsafe {
            (image_base.offset(dos_header.e_lfanew.try_into().unwrap())
                as *const IMAGE_NT_HEADERS64)
                .read()
        };
        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            return Err("Image signature corrupt".to_string());
        }

        let file_header: IMAGE_FILE_HEADER = nt_headers.FileHeader;
        let optional_header: IMAGE_OPTIONAL_HEADER64 = nt_headers.OptionalHeader;
        let section_headers = unsafe {
            image_bytes
                .as_ptr()
                .offset(pre_dos_header.e_lfanew.try_into().unwrap())
                .offset(
                    core::mem::size_of::<IMAGE_NT_HEADERS64>()
                        .try_into()
                        .unwrap(),
                ) as *const IMAGE_SECTION_HEADER
        };

        let export_address_table = unsafe {
            image_base.offset(
                optional_header.DataDirectory[0]
                    .VirtualAddress
                    .try_into()
                    .unwrap(),
            ) as *const IMAGE_EXPORT_DIRECTORY
        };
        let import_address_table = unsafe {
            image_base.offset(
                optional_header.DataDirectory[1]
                    .VirtualAddress
                    .try_into()
                    .unwrap(),
            ) as *const IMAGE_IMPORT_DESCRIPTOR
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
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::PE;
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

    /* note: image size on disk != image size in memory.
    #[test]
    fn image_size_correct() {
        let notepad = PE::from_disk(&"C:\\Windows\\system32\\notepad.exe".to_string()).unwrap();
        assert_eq!(fs::metadata("C:\\Windows\\system32\\notepad.exe").unwrap().len(), notepad.image_size as u64);
    }
    */
}
