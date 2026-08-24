//! Minimal hand-rolled UEFI type/protocol bindings — ONLY the §3.3 protocol whitelist.
//! No uefi-rs: the loader binds to FROZEN contracts (the UEFI 2.10 protocol ABIs) so
//! there is ~zero external churn in the boot-trust window.
//!
//! Every struct cites its UEFI 2.10 section. Field ORDER is the ABI — a wrong slot is
//! a silent miscall; the OVMF gate (§9) is the empirical proof, exactly as
//! `installer_syscall.rs` FFI is proven. Unused table slots are kept as named `usize`
//! placeholders (every slot is one pointer wide on x86_64) so the used slots sit at
//! their spec offsets.

#![allow(dead_code)]

use ::core::ffi::c_void;

/// UEFI 2.10 §2.3.1: EFI_STATUS is UINTN; error codes set the high bit.
pub type EfiStatus = usize;
/// UEFI 2.10 §2.3.1: EFI_HANDLE is an opaque pointer.
pub type Handle = *mut c_void;

pub const EFI_SUCCESS: EfiStatus = 0;
pub const EFI_INVALID_PARAMETER: EfiStatus = 0x8000_0000_0000_0002;
pub const EFI_UNSUPPORTED: EfiStatus = 0x8000_0000_0000_0003;
pub const EFI_BUFFER_TOO_SMALL: EfiStatus = 0x8000_0000_0000_0005;
pub const EFI_NOT_FOUND: EfiStatus = 0x8000_0000_0000_000E;
pub const EFI_ACCESS_DENIED: EfiStatus = 0x8000_0000_0000_000F;
pub const EFI_SECURITY_VIOLATION: EfiStatus = 0x8000_0000_0000_001A;

/// EFI_GUID (UEFI 2.10 §A.2): three little-endian scalar fields + 8 raw bytes.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EfiGuid {
    pub d1: u32,
    pub d2: u16,
    pub d3: u16,
    pub d4: [u8; 8],
}

                                                                                        
                                                                                     
pub const INITRD_MEDIA_GUID: EfiGuid = EfiGuid {
    d1: 0x5568_e427,
    d2: 0x68fc,
    d3: 0x4f3d,
    d4: [0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68],
};

                                                                                      
                                           
pub const EFI_GLOBAL_VARIABLE: EfiGuid = EfiGuid {
    d1: 0x8be4_df61,
    d2: 0x93ca,
    d3: 0x11d2,
    d4: [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
};

                                                                                         
pub const LOADED_IMAGE_GUID: EfiGuid = EfiGuid {
    d1: 0x5b1b_31a1,
    d2: 0x9562,
    d3: 0x11d2,
    d4: [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

                                                                                      
pub const SIMPLE_FS_GUID: EfiGuid = EfiGuid {
    d1: 0x964e_5b22,
    d2: 0x6459,
    d3: 0x11d2,
    d4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

                                                                     
pub const FILE_INFO_GUID: EfiGuid = EfiGuid {
    d1: 0x0957_6e92,
    d2: 0x6d3f,
    d3: 0x11d2,
    d4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

                                                                               
pub const DEVICE_PATH_GUID: EfiGuid = EfiGuid {
    d1: 0x0957_6e91,
    d2: 0x6d3f,
    d3: 0x11d2,
    d4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

                                                                              
pub const LOAD_FILE2_GUID: EfiGuid = EfiGuid {
    d1: 0x4006_c0c1,
    d2: 0xfcb3,
    d3: 0x403e,
    d4: [0x99, 0x6d, 0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d],
};

/// EFI_TABLE_HEADER (UEFI 2.10 §4.2.1) — 24 bytes.
#[repr(C)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

/// EFI_SYSTEM_TABLE (UEFI 2.10 §4.3.1).
#[repr(C)]
pub struct SystemTable {
    pub hdr: TableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: Handle,
    pub con_in: usize,                                              
    pub console_out_handle: Handle,
    pub con_out: *mut SimpleTextOutput,
    pub standard_error_handle: Handle,
    pub std_err: usize,                                               
    pub runtime_services: *mut RuntimeServices,
    pub boot_services: *mut BootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: usize,                                       
}

/// EFI_BOOT_SERVICES (UEFI 2.10 §4.4.1; slot order per the spec's service groups).
/// Unused slots are named `usize` placeholders so used slots keep spec offsets.
#[repr(C)]
pub struct BootServices {
    pub hdr: TableHeader,
                             
    pub raise_tpl: usize,
    pub restore_tpl: usize,
                      
    pub allocate_pages: usize,
    pub free_pages: usize,
    pub get_memory_map: usize,
    pub allocate_pool:
        unsafe extern "efiapi" fn(pool_type: u32, size: usize, buffer: *mut *mut u8) -> EfiStatus,
    pub free_pool: usize,
                             
    pub create_event: usize,
    pub set_timer: usize,
    pub wait_for_event: usize,
    pub signal_event: usize,
    pub close_event: usize,
    pub check_event: usize,
                                
    pub install_protocol_interface: usize,
    pub reinstall_protocol_interface: usize,
    pub uninstall_protocol_interface: usize,
    pub handle_protocol: unsafe extern "efiapi" fn(
        handle: Handle,
        protocol: *const EfiGuid,
        interface: *mut *mut c_void,
    ) -> EfiStatus,
    pub reserved: usize,
    pub register_protocol_notify: usize,
    pub locate_handle: usize,
    pub locate_device_path: usize,
    pub install_configuration_table: usize,
                     
    pub load_image: unsafe extern "efiapi" fn(
        boot_policy: u8,
        parent_image_handle: Handle,
        device_path: *const u8,
        source_buffer: *const u8,
        source_size: usize,
        image_handle: *mut Handle,
    ) -> EfiStatus,
    pub start_image: unsafe extern "efiapi" fn(
        image_handle: Handle,
        exit_data_size: *mut usize,
        exit_data: *mut *mut u16,
    ) -> EfiStatus,
    pub exit: usize,
    pub unload_image: usize,
    pub exit_boot_services: usize,
                             
    pub get_next_monotonic_count: usize,
    pub stall: unsafe extern "efiapi" fn(microseconds: usize) -> EfiStatus,
    pub set_watchdog_timer: usize,
                                        
    pub connect_controller: usize,
    pub disconnect_controller: usize,
                                               
    pub open_protocol: usize,
    pub close_protocol: usize,
    pub open_protocol_information: usize,
                       
    pub protocols_per_handle: usize,
    pub locate_handle_buffer: usize,
    pub locate_protocol: usize,
    /// Variadic: (guid*, interface*) pairs, NULL-guid terminated (UEFI 2.10 §7.3.9).
    pub install_multiple_protocol_interfaces:
        unsafe extern "efiapi" fn(handle: *mut Handle, ...) -> EfiStatus,
    pub uninstall_multiple_protocol_interfaces: usize,
                          
    pub calculate_crc32: usize,
                             
    pub copy_mem: usize,
    pub set_mem: usize,
    pub create_event_ex: usize,
}

/// EFI_RUNTIME_SERVICES (UEFI 2.10 §4.5.1).
#[repr(C)]
pub struct RuntimeServices {
    pub hdr: TableHeader,
                    
    pub get_time: usize,
    pub set_time: usize,
    pub get_wakeup_time: usize,
    pub set_wakeup_time: usize,
                              
    pub set_virtual_address_map: usize,
    pub convert_pointer: usize,
                        
    pub get_variable: unsafe extern "efiapi" fn(
        variable_name: *const u16,
        vendor_guid: *const EfiGuid,
        attributes: *mut u32,
        data_size: *mut usize,
        data: *mut u8,
    ) -> EfiStatus,
    pub get_next_variable_name: usize,
    pub set_variable: usize,
                             
    pub get_next_high_monotonic_count: usize,
    pub reset_system: usize,
                                
    pub update_capsule: usize,
    pub query_capsule_capabilities: usize,
                             
    pub query_variable_info: usize,
}

/// EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL (UEFI 2.10 §12.4) — OutputString at slot 1.
#[repr(C)]
pub struct SimpleTextOutput {
    pub reset: usize,
    pub output_string:
        unsafe extern "efiapi" fn(this: *mut SimpleTextOutput, string: *const u16) -> EfiStatus,
    pub test_string: usize,
    pub query_mode: usize,
    pub set_mode: usize,
    pub set_attribute: usize,
    pub clear_screen: usize,
    pub set_cursor_position: usize,
    pub enable_cursor: usize,
    pub mode: usize,
}

/// EFI_LOADED_IMAGE_PROTOCOL (UEFI 2.10 §9.1). Natural alignment pads revision→8 and
/// load_options_size→8, matching the C layout.
#[repr(C)]
pub struct LoadedImage {
    pub revision: u32,
    pub parent_handle: Handle,
    pub system_table: *mut SystemTable,
    pub device_handle: Handle,
    pub file_path: *const u8,                             
    pub reserved: *mut c_void,
    pub load_options_size: u32,
    pub load_options: *mut c_void,
    pub image_base: *mut c_void,
    pub image_size: u64,
    pub image_code_type: u32,
    pub image_data_type: u32,
    pub unload: usize,
}

/// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL (UEFI 2.10 §13.4).
#[repr(C)]
pub struct SimpleFileSystem {
    pub revision: u64,
    pub open_volume: unsafe extern "efiapi" fn(
        this: *mut SimpleFileSystem,
        root: *mut *mut FileProtocol,
    ) -> EfiStatus,
}

/// EFI_FILE_PROTOCOL (UEFI 2.10 §13.5; revision-1 slots — the v2 *Ex slots trail the
/// struct and are never touched).
#[repr(C)]
pub struct FileProtocol {
    pub revision: u64,
    pub open: unsafe extern "efiapi" fn(
        this: *mut FileProtocol,
        new_handle: *mut *mut FileProtocol,
        file_name: *const u16,
        open_mode: u64,
        attributes: u64,
    ) -> EfiStatus,
    pub close: unsafe extern "efiapi" fn(this: *mut FileProtocol) -> EfiStatus,
    pub delete: usize,
    pub read: unsafe extern "efiapi" fn(
        this: *mut FileProtocol,
        buffer_size: *mut usize,
        buffer: *mut u8,
    ) -> EfiStatus,
    pub write: usize,
    pub get_position: usize,
    pub set_position: usize,
    pub get_info: unsafe extern "efiapi" fn(
        this: *mut FileProtocol,
        information_type: *const EfiGuid,
        buffer_size: *mut usize,
        buffer: *mut u8,
    ) -> EfiStatus,
    pub set_info: usize,
    pub flush: usize,
}

/// §13.5.2: EFI_FILE_MODE_READ.
pub const EFI_FILE_MODE_READ: u64 = 0x0000_0000_0000_0001;

/// §7.2.4: EfiLoaderData memory type for AllocatePool.
pub const EFI_LOADER_DATA: u32 = 2;

/// EFI_LOAD_FILE2_PROTOCOL (UEFI 2.10 §13.2): a single slot. The serving struct in
/// main.rs extends this layout with private fields AFTER the slot (the consumer only
/// knows the protocol prefix — the standard container pattern).
#[repr(C)]
pub struct LoadFile2 {
    pub load_file: unsafe extern "efiapi" fn(
        this: *mut LoadFile2,
        file_path: *const u8,
        boot_policy: u8,
        buffer_size: *mut usize,
        buffer: *mut u8,
    ) -> EfiStatus,
}
