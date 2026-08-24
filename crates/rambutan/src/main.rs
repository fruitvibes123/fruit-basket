//! rambutan — the hand-rolled UEFI Secure Boot loader (the
//! `efi-loader` crate under its fruit-orchard name).
//!
//! `\EFI\BOOT\BOOTX64.EFI`: the firmware SB-verifies THIS image; it then `LoadImage`s a
//! plain bzImage (the firmware re-verifies it against db), bakes the kernel cmdline via
//! `LoadOptions`, and serves a SHA-256-digest-gated initrd over `LoadFile2` (spec §3).
//! Boot policy lives HERE, in code we own — not in kernel build-config (the superseded
//! kernel-stub design).
//!
//! Split (plan L1): `core.rs` = host-tested pure functions; `efi.rs` = hand-rolled
//! minimal UEFI bindings; this file = the §3.2 control flow, built only for
//! `--target x86_64-unknown-uefi` and proven at the OVMF boot gate (host-unverifiable,
//! exactly as `installer_syscall.rs` FFI is). Host builds compile a stub `main` so
//! `cargo test`/clippy stay green.
//!
//! Failure posture (spec §3.2): EVERY error path prints one line to ConOut and halts —
//! no fallback boot path, no reset loop, no shell, no retry. Recovery from a halted
//! verified boot is a physical operator action (§7.2).

#![cfg_attr(target_os = "uefi", no_std)]
#![cfg_attr(target_os = "uefi", no_main)]

                                                                                         
                                                                                 
                                                                                   
                                                                                        
#[cfg_attr(not(target_os = "uefi"), allow(dead_code))]
mod core;
mod efi;
                                                                                   
                                                                                
                                                                                       
#[cfg(test)]
mod hex;

/// The per-build policy constants (cmdline / initrd digest / SB requirement), baked by
/// build.rs from RECIPES_LOADER_* env — see build.rs for the fail-closed contract.
#[cfg_attr(not(target_os = "uefi"), allow(dead_code))]
mod baked {
    include!(concat!(env!("OUT_DIR"), "/baked.rs"));
}

#[cfg(target_os = "uefi")]
mod loader {
    use crate::{baked, core, efi};
    use ::core::ffi::c_void;
    use ::core::ptr;

    /// Fail-closed halt: no unwinding machinery, no fallback boot path (spec §3.2).
    /// A panic can only come from a code bug (e.g. slice bounds) — spin; the operator
    /// recovers physically (§7.2).
    #[panic_handler]
    fn panic(_info: &::core::panic::PanicInfo) -> ! {
        loop {
            ::core::hint::spin_loop();
        }
    }

    /// Single-threaded boot-services cell: TPL_APPLICATION, one CPU, no events — the
    /// only accessors are this image's own straight-line code + the kernel stub's
    /// LoadFile2 callback, which runs strictly after every write.
    #[repr(transparent)]
    struct BootCell<T>(::core::cell::UnsafeCell<T>);
                                                                                        
    unsafe impl<T> Sync for BootCell<T> {}

    /// The LoadFile2 server (spec §3.2.7): the protocol slot FIRST (the consumer only
    /// knows that prefix), then the private verified-buffer fields the callback reads.
    #[repr(C)]
    struct InitrdServer {
        proto: efi::LoadFile2,
        ptr: *const u8,
        len: usize,
    }

    /// Statics live in the PE image — valid for the whole boot-services epoch (the
    /// loader image stays resident across StartImage; spec §3.3 lifetime note).
    static INITRD_SERVER: BootCell<InitrdServer> =
        BootCell(::core::cell::UnsafeCell::new(InitrdServer {
            proto: efi::LoadFile2 {
                load_file: serve_initrd,
            },
            ptr: ptr::null(),
            len: 0,
        }));
    static INITRD_DEVICE_PATH: BootCell<[u8; 24]> =
        BootCell(::core::cell::UnsafeCell::new([0u8; 24]));
    /// The kernel's LoadOptions buffer — must stay valid while the stub parses it
    /// (during StartImage). 2048 UCS-2 units ≥ any cmdline render_uefi_cmdline emits.
    static CMDLINE_UCS2: BootCell<[u16; 2048]> =
        BootCell(::core::cell::UnsafeCell::new([0u16; 2048]));

    /// UCS-2 literals at compile time (ASCII-only input).
    const fn ucs2<const N: usize>(s: &str) -> [u16; N] {
        let b = s.as_bytes();
        assert!(b.len() + 1 == N, "N must be len+1 (NUL)");
        let mut out = [0u16; N];
        let mut i = 0;
        while i < b.len() {
            assert!(b[i].is_ascii(), "UCS-2 literals are ASCII-only");
            out[i] = b[i] as u16;
            i += 1;
        }
        out
    }

    const SECURE_BOOT_VAR: [u16; 11] = ucs2("SecureBoot");
    const VMLINUZ: [u16; 9] = ucs2("\\vmlinuz");
    const INITRD: [u16; 8] = ucs2("\\initrd");

    /// Corruption-sanity ceilings for the ESP artifacts `read_whole_file` loads (finding
    /// M1, 2026-07-18 deep review). NOT a security mechanism: a corrupt size cannot inject
    /// trusted content — the kernel is db-verified by LoadImage and the initrd is
    /// digest-gated, both DOWNSTREAM of this read; `EFI_FILE_INFO`/`FileSize` are
    /// firmware-reported FAT metadata that nothing signs. Without a cap, a corrupt
    /// filesystem / RAID controller reporting a preposterous size merely makes the later
    /// AllocatePool fail generically; the cap turns that into an early, fail-closed
    /// refusal. Sized far above any legitimate runtime kernel (~15 MiB bzImage) or
    /// initramfs (tens of MiB) so a real artifact is never rejected.
    ///
    /// These are compile-time source consts, so they bake into EVERY rambutan build —
    /// the runtime loader AND the USB-installer loader (the same crate rebuilt with
    /// different baked policy; 2026-06-24 installer spec §4), not one "separate image".
    /// They don't reject the installer's initrd because it is runtime-sized too: the
    /// installer's multi-hundred-MB box.img rides a separate ext4 partition read by
    /// initramfs-init after handoff, never through `read_whole_file` (installer spec §12).
    /// A future images-in-initrd installer would have to raise MAX_INITRD_BYTES — which
    /// is why these live in shared source, not scoped to one build.
    const MAX_KERNEL_BYTES: usize = 128 * 1024 * 1024;
    const MAX_INITRD_BYTES: usize = 512 * 1024 * 1024;
    /// `EFI_FILE_INFO` is a ~80-byte struct + a NUL-terminated UCS-2 filename (FAT LFN
    /// ≤ 255 chars → under ~600 bytes for any real entry). Cap the metadata allocation
    /// well above that so a corrupt driver-computed `info_size` cannot drive an unbounded
    /// allocation either (M1 — the sibling of the file-bytes cap).
    const MAX_FILE_INFO_BYTES: usize = 4 * 1024;

    /// §3.2 step 7 + UEFI §13.2: the two-call LoadFile2 contract. Serves EXACTLY the
    /// digest-verified pool buffer recorded in `InitrdServer` — the only initrd source
    /// No TOCTOU: the bytes served are the bytes hashed, never re-read from disk.
    unsafe extern "efiapi" fn serve_initrd(
        this: *mut efi::LoadFile2,
        _file_path: *const u8,
        boot_policy: u8,
        buffer_size: *mut usize,
        buffer: *mut u8,
    ) -> efi::EfiStatus {
        if this.is_null() || buffer_size.is_null() {
            return efi::EFI_INVALID_PARAMETER;
        }
                                                                               
        if boot_policy != 0 {
            return efi::EFI_UNSUPPORTED;
        }
        let server = unsafe { &*(this as *const InitrdServer) };
        if server.ptr.is_null() {
            return efi::EFI_NOT_FOUND;
        }
        if buffer.is_null() || unsafe { *buffer_size } < server.len {
            unsafe { *buffer_size = server.len };
            return efi::EFI_BUFFER_TOO_SMALL;
        }
        unsafe {
            ptr::copy_nonoverlapping(server.ptr, buffer, server.len);
            *buffer_size = server.len;
        }
        efi::EFI_SUCCESS
    }

    /// Print an ASCII str to ConOut (chunked UCS-2; '\n' expanded to CRLF).
    fn con_print(st: &efi::SystemTable, s: &str) {
        let con = st.con_out;
        if con.is_null() {
            return;
        }
        let mut buf = [0u16; 65];
        let mut n = 0usize;
        let flush = |buf: &mut [u16; 65], n: &mut usize| {
            buf[*n] = 0;
                                                                         
            unsafe { ((*con).output_string)(con, buf.as_ptr()) };
            *n = 0;
        };
        for &b in s.as_bytes() {
            if n >= 63 {
                flush(&mut buf, &mut n);
            }
            if b == b'\n' {
                buf[n] = u16::from(b'\r');
                n += 1;
            }
            buf[n] = u16::from(if b.is_ascii() { b } else { b'?' });
            n += 1;
        }
        if n > 0 {
            flush(&mut buf, &mut n);
        }
    }

    /// Print a status code as hex (for gate debugging — which step refused and why).
    fn con_print_hex(st: &efi::SystemTable, v: usize) {
        let mut buf = [0u16; 19];
        buf[0] = u16::from(b'0');
        buf[1] = u16::from(b'x');
        for i in 0..16 {
            let nib = ((v >> ((15 - i) * 4)) & 0xF) as u8;
            buf[2 + i] = u16::from(if nib < 10 {
                b'0' + nib
            } else {
                b'a' + nib - 10
            });
        }
        buf[18] = 0;
        let con = st.con_out;
        if !con.is_null() {
                                                        
            unsafe { ((*con).output_string)(con, buf.as_ptr()) };
        }
    }

    /// Fail-closed terminal state (spec §3.2): one-line reason, then stall forever.
    fn halt(st: &efi::SystemTable, msg: &str, status: Option<efi::EfiStatus>) -> ! {
        con_print(st, "rambutan: ");
        con_print(st, msg);
        if let Some(code) = status {
            con_print(st, " status=");
            con_print_hex(st, code);
        }
        con_print(st, " -- halted (fail closed)\n");
        let bs = st.boot_services;
        loop {
            if !bs.is_null() {
                                                                   
                unsafe { ((*bs).stall)(1_000_000) };
            }
        }
    }

    /// Walk a device path to find its byte length EXCLUDING the END node (nodes are
    /// {type u8, subtype u8, len u16le}; END = 0x7F/0xFF). Bounded — a malformed path
    /// (len < 4 or > 1 KiB total) returns None and the caller halts.
    unsafe fn device_path_len_without_end(dp: *const u8) -> Option<usize> {
        let mut off = 0usize;
        loop {
            if off > 1024 {
                return None;
            }
                                                                                      
                                                                                        
            let ty = unsafe { *dp.add(off) };
            let sub = unsafe { *dp.add(off + 1) };
            let len = u16::from_le_bytes([unsafe { *dp.add(off + 2) }, unsafe { *dp.add(off + 3) }])
                as usize;
            if ty == 0x7F && sub == 0xFF {
                return Some(off);
            }
            if len < 4 {
                return None;
            }
            off += len;
        }
    }

    /// §3.2 step 3: open a file on the ESP root, size it via GetInfo (two-call), read
    /// it whole into an AllocatePool buffer (looped Read; short read = halt-worthy
    /// `None`). BOTH pool allocations are bounded first (finding M1): the `EFI_FILE_INFO`
    /// buffer to `MAX_FILE_INFO_BYTES`, the file bytes to `max_bytes` — an out-of-range
    /// size is refused as a clean early `None`. Returns (buffer, length).
    unsafe fn read_whole_file(
        bs: &efi::BootServices,
        root: *mut efi::FileProtocol,
        name: *const u16,
        max_bytes: usize,
    ) -> Option<(*mut u8, usize)> {
        let mut file: *mut efi::FileProtocol = ptr::null_mut();
                                                                               
        let st = unsafe { ((*root).open)(root, &mut file, name, efi::EFI_FILE_MODE_READ, 0) };
        if st != efi::EFI_SUCCESS || file.is_null() {
            return None;
        }
                                                                                   
        let mut info_size = 0usize;
                                                                                     
                           
        let st = unsafe {
            ((*file).get_info)(file, &efi::FILE_INFO_GUID, &mut info_size, ptr::null_mut())
        };
                                                                                      
                                                                                        
                                                                                          
        if st != efi::EFI_BUFFER_TOO_SMALL
            || !core::alloc_size_in_bounds(info_size, 16, MAX_FILE_INFO_BYTES)
        {
            return None;
        }
        let mut info_buf: *mut u8 = ptr::null_mut();
                                            
        if unsafe { (bs.allocate_pool)(efi::EFI_LOADER_DATA, info_size, &mut info_buf) }
            != efi::EFI_SUCCESS
            || info_buf.is_null()
        {
            return None;
        }
                                                
        let st =
            unsafe { ((*file).get_info)(file, &efi::FILE_INFO_GUID, &mut info_size, info_buf) };
        if st != efi::EFI_SUCCESS {
            return None;
        }
                                                                   
                                                                                  
                                                                                         
        let file_size = unsafe { ptr::read_unaligned(info_buf.add(8) as *const u64) } as usize;
                                                                                      
                                                                                       
        if !core::alloc_size_in_bounds(file_size, 1, max_bytes) {
            return None;
        }
        let mut data: *mut u8 = ptr::null_mut();
                                                   
        if unsafe { (bs.allocate_pool)(efi::EFI_LOADER_DATA, file_size, &mut data) }
            != efi::EFI_SUCCESS
            || data.is_null()
        {
            return None;
        }
        let mut total = 0usize;
        while total < file_size {
            let mut chunk = file_size - total;
                                                                                     
            let st = unsafe { ((*file).read)(file, &mut chunk, data.add(total)) };
            if st != efi::EFI_SUCCESS || chunk == 0 {
                return None;                                                          
            }
            total += chunk;
        }
                                                                      
        unsafe { ((*file).close)(file) };
        Some((data, file_size))
    }

    /// The §3.2 eight-step verified-boot flow. Every deviation is print+halt.
    ///
    /// SB-trust note (spec §2): the firmware verified THIS image before running it;
    /// step 5's LoadImage makes the firmware re-verify the KERNEL against db (the
                  
    /// platform's Security2 arch protocol hashes the supplied buffer);
    /// step 4 binds the initrd to the digest inside this signed image; step 6 bakes
    /// the cmdline from this signed image. Nothing executable or policy-bearing comes
    /// from outside the verified set.
    pub fn boot(image_handle: efi::Handle, st_ptr: *mut efi::SystemTable) -> ! {
        if st_ptr.is_null() {
                                                                         
            loop {
                ::core::hint::spin_loop();
            }
        }
                                                                                   
        let st = unsafe { &*st_ptr };
        if st.boot_services.is_null() || st.runtime_services.is_null() {
            loop {
                ::core::hint::spin_loop();
            }
        }
                                                               
        let bs = unsafe { &*st.boot_services };
        let rs = unsafe { &*st.runtime_services };

                                                                                       
                                                                               
        let mut li_ptr: *mut c_void = ptr::null_mut();
                                                                                        
        let s = unsafe { (bs.handle_protocol)(image_handle, &efi::LOADED_IMAGE_GUID, &mut li_ptr) };
        if s != efi::EFI_SUCCESS || li_ptr.is_null() {
            halt(st, "own LoadedImage protocol unavailable", Some(s));
        }
        let own_li = li_ptr as *mut efi::LoadedImage;
                                                           
        let esp_device = unsafe { (*own_li).device_handle };

                                                                                          
                                                      
        if baked::SB_REQUIRED {
            let mut val = [0u8; 8];
            let mut size = val.len();
                                                                                      
            let s = unsafe {
                (rs.get_variable)(
                    SECURE_BOOT_VAR.as_ptr(),
                    &efi::EFI_GLOBAL_VARIABLE,
                    ptr::null_mut(),
                    &mut size,
                    val.as_mut_ptr(),
                )
            };
            let value = if s == efi::EFI_SUCCESS && size <= val.len() {
                Some(&val[..size])
            } else {
                None
            };
            if !core::sb_check_passes(s, value) {
                halt(
                    st,
                    "SB_REQUIRED but SecureBoot!=0x01 (absent/off/error)",
                    Some(s),
                );
            }
        }

                                                                                   
                                    
        let mut fs_ptr: *mut c_void = ptr::null_mut();
                                                                
        let s = unsafe { (bs.handle_protocol)(esp_device, &efi::SIMPLE_FS_GUID, &mut fs_ptr) };
        if s != efi::EFI_SUCCESS || fs_ptr.is_null() {
            halt(st, "own-ESP SimpleFileSystem unavailable", Some(s));
        }
        let fs = fs_ptr as *mut efi::SimpleFileSystem;
        let mut root: *mut efi::FileProtocol = ptr::null_mut();
                                                       
        let s = unsafe { ((*fs).open_volume)(fs, &mut root) };
        if s != efi::EFI_SUCCESS || root.is_null() {
            halt(st, "ESP OpenVolume failed", Some(s));
        }
                                                                        
        let Some((kernel_buf, kernel_len)) =
            (unsafe { read_whole_file(bs, root, VMLINUZ.as_ptr(), MAX_KERNEL_BYTES) })
        else {
            halt(st, "reading \\vmlinuz failed", None);
        };
        let Some((initrd_buf, initrd_len)) =
            (unsafe { read_whole_file(bs, root, INITRD.as_ptr(), MAX_INITRD_BYTES) })
        else {
            halt(st, "reading \\initrd failed", None);
        };

                                                                                  
                                                                              
        let initrd = unsafe { ::core::slice::from_raw_parts(initrd_buf, initrd_len) };
        if !core::initrd_digest_ok(initrd, &baked::INITRD_SHA256) {
            halt(st, "initrd digest mismatch", None);
        }

                                                                                  
                                                                                 
                                                                                   
        let mut dp_buf = [0u8; 512];
        let mut esp_dp_ptr: *mut c_void = ptr::null_mut();
                                                                    
        let s =
            unsafe { (bs.handle_protocol)(esp_device, &efi::DEVICE_PATH_GUID, &mut esp_dp_ptr) };
        if s != efi::EFI_SUCCESS || esp_dp_ptr.is_null() {
            halt(st, "own-ESP DevicePath unavailable", Some(s));
        }
                                                                                
        let Some(parent_len) = (unsafe { device_path_len_without_end(esp_dp_ptr as *const u8) })
        else {
            halt(st, "own-ESP DevicePath malformed", None);
        };
        if parent_len + 26 > dp_buf.len() {
            halt(st, "own-ESP DevicePath too long", None);
        }
                                                                
        let parent = unsafe { ::core::slice::from_raw_parts(esp_dp_ptr as *const u8, parent_len) };
        let Some(_dp_len) = core::build_image_device_path(parent, "\\vmlinuz", &mut dp_buf) else {
            halt(st, "vmlinuz device path build failed", None);
        };
        let mut kernel_handle: efi::Handle = ptr::null_mut();
                                                                                        
                                                                                       
        let s = unsafe {
            (bs.load_image)(
                0,
                image_handle,
                dp_buf.as_ptr(),
                kernel_buf,
                kernel_len,
                &mut kernel_handle,
            )
        };
        if s != efi::EFI_SUCCESS || kernel_handle.is_null() {
                                                                                     
                                                                                     
                                                 
            halt(st, "LoadImage(vmlinuz) refused", Some(s));
        }

                                                                       
        let mut kli_ptr: *mut c_void = ptr::null_mut();
                                                             
        let s =
            unsafe { (bs.handle_protocol)(kernel_handle, &efi::LOADED_IMAGE_GUID, &mut kli_ptr) };
        if s != efi::EFI_SUCCESS || kli_ptr.is_null() {
            halt(st, "kernel LoadedImage protocol unavailable", Some(s));
        }
        let cmdline_buf = CMDLINE_UCS2.0.get();
                                                                                  
        let Some(n) =
            core::encode_cmdline_ucs2(baked::KERNEL_CMDLINE, unsafe { &mut *cmdline_buf })
        else {
            halt(
                st,
                "baked cmdline not encodable (too long / bad byte)",
                None,
            );
        };
        unsafe {
                                                                                  
                                                                  
            let kli = kli_ptr as *mut efi::LoadedImage;
            (*kli).load_options = cmdline_buf as *mut c_void;
            (*kli).load_options_size = core::load_options_size_bytes(n);
        }

                                                                                      
                                                                      
        unsafe {
                                                                                    
            let dp = INITRD_DEVICE_PATH.0.get();
            *dp = core::initrd_device_path_bytes();
            let server = INITRD_SERVER.0.get();
            (*server).ptr = initrd_buf;
            (*server).len = initrd_len;
            let mut fresh: efi::Handle = ptr::null_mut();
                                                                                         
            let s = (bs.install_multiple_protocol_interfaces)(
                &mut fresh,
                &efi::DEVICE_PATH_GUID as *const efi::EfiGuid,
                dp as *const c_void,
                &efi::LOAD_FILE2_GUID as *const efi::EfiGuid,
                server as *const c_void,
                ptr::null::<efi::EfiGuid>(),
            );
            if s != efi::EFI_SUCCESS {
                halt(st, "installing the initrd LoadFile2 handle failed", Some(s));
            }
        }

                                             
                                                                                   
        let s = unsafe { (bs.start_image)(kernel_handle, ptr::null_mut(), ptr::null_mut()) };
        halt(st, "StartImage returned", Some(s));
    }
}

#[cfg(target_os = "uefi")]
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(
    image_handle: efi::Handle,
    system_table: *mut efi::SystemTable,
) -> efi::EfiStatus {
    loader::boot(image_handle, system_table)
}

/// Host-target stub: the real entry is `efi_main` (uefi target only).
#[cfg(not(target_os = "uefi"))]
fn main() {}
