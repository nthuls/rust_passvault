// src/firefox/nss.rs
use libloading::{Library, Symbol};
use std::ffi::{CString, c_void, c_char, c_int, c_uint};
use std::ptr;
use std::path::Path;
use base64::{engine::general_purpose, Engine as _};

// NSS function types
type NssInit = unsafe extern "C" fn(*const c_char) -> c_int;
type NssShutdown = unsafe extern "C" fn() -> c_int;
type Pk11GetInternalKeySlot = unsafe extern "C" fn() -> *mut c_void;
type Pk11FreeSlot = unsafe extern "C" fn(*mut c_void);
type Pk11NeedLogin = unsafe extern "C" fn(*mut c_void) -> c_int;
type Pk11CheckUserPassword = unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int;
type Pk11SdrDecrypt = unsafe extern "C" fn(*mut SECItem, *mut SECItem, *mut c_void) -> c_int;
type SecItemZfreeItem = unsafe extern "C" fn(*mut SECItem, c_int);

// NSS structures
#[repr(C)]
struct SECItem {
    type_: c_uint,
    data: *mut u8,
    len: c_uint,
}

pub struct NSSDecryptor {
    lib: Option<Library>,
    nss_init: Option<Symbol<'static, NssInit>>,
    nss_shutdown: Option<Symbol<'static, NssShutdown>>,
    pk11_get_internal_key_slot: Option<Symbol<'static, Pk11GetInternalKeySlot>>,
    pk11_free_slot: Option<Symbol<'static, Pk11FreeSlot>>,
    pk11_need_login: Option<Symbol<'static, Pk11NeedLogin>>,
    pk11_check_user_password: Option<Symbol<'static, Pk11CheckUserPassword>>,
    pk11sdr_decrypt: Option<Symbol<'static, Pk11SdrDecrypt>>,
    secitem_zfree_item: Option<Symbol<'static, SecItemZfreeItem>>,
}

impl NSSDecryptor {
    pub fn new() -> Self {
        Self {
            lib: None,
            nss_init: None,
            nss_shutdown: None,
            pk11_get_internal_key_slot: None,
            pk11_free_slot: None,
            pk11_need_login: None,
            pk11_check_user_password: None,
            pk11sdr_decrypt: None,
            secitem_zfree_item: None,
        }
    }

    fn load_nss(&mut self) -> Result<(), String> {
        let nss_paths = self.find_nss_paths();

        for path in nss_paths {
            if let Ok(lib) = unsafe { Library::new(&path) } {
                unsafe {
                    let init = lib.get::<NssInit>(b"NSS_Init").ok();
                    let shutdown = lib.get::<NssShutdown>(b"NSS_Shutdown").ok();
                    let get_slot = lib.get::<Pk11GetInternalKeySlot>(b"PK11_GetInternalKeySlot").ok();
                    let free_slot = lib.get::<Pk11FreeSlot>(b"PK11_FreeSlot").ok();
                    let need_login = lib.get::<Pk11NeedLogin>(b"PK11_NeedLogin").ok();
                    let check_pw = lib.get::<Pk11CheckUserPassword>(b"PK11_CheckUserPassword").ok();
                    let decrypt = lib.get::<Pk11SdrDecrypt>(b"PK11SDR_Decrypt").ok();
                    let zfree = lib.get::<SecItemZfreeItem>(b"SECITEM_ZfreeItem").ok();

                    if let (Some(i), Some(s), Some(gs), Some(fs), Some(nl), Some(cp), Some(d), Some(z)) =
                        (init, shutdown, get_slot, free_slot, need_login, check_pw, decrypt, zfree)
                    {
                        self.nss_init = Some(std::mem::transmute(i));
                        self.nss_shutdown = Some(std::mem::transmute(s));
                        self.pk11_get_internal_key_slot = Some(std::mem::transmute(gs));
                        self.pk11_free_slot = Some(std::mem::transmute(fs));
                        self.pk11_need_login = Some(std::mem::transmute(nl));
                        self.pk11_check_user_password = Some(std::mem::transmute(cp));
                        self.pk11sdr_decrypt = Some(std::mem::transmute(d));
                        self.secitem_zfree_item = Some(std::mem::transmute(z));

                        self.lib = Some(lib);
                        return Ok(());
                    }
                }
            }
        }

        Err("Failed to load NSS library".to_string())
    }

    fn find_nss_paths(&self) -> Vec<String> {
        if cfg!(target_os = "windows") {
            vec![
                "nss3.dll".into(),
                "C:\\Program Files\\Mozilla Firefox\\nss3.dll".into(),
                "C:\\Program Files (x86)\\Mozilla Firefox\\nss3.dll".into(),
            ]
        } else if cfg!(target_os = "macos") {
            vec![
                "libnss3.dylib".into(),
                "/usr/local/lib/libnss3.dylib".into(),
                "/usr/local/opt/nss/lib/libnss3.dylib".into(),
                "/Applications/Firefox.app/Contents/MacOS/libnss3.dylib".into(),
            ]
        } else {
            vec![
                "libnss3.so".into(),
                "/usr/lib/libnss3.so".into(),
                "/usr/lib64/libnss3.so".into(),
                "/usr/local/lib/libnss3.so".into(),
            ]
        }
    }

    pub fn initialize(&mut self, profile_path: &Path, master_password: Option<&str>) -> Result<(), String> {
        self.load_nss()?;
        let profile_str = format!("sql:{}", profile_path.display());
        let c_profile = CString::new(profile_str).map_err(|e| e.to_string())?;

        let nss_init = self.nss_init.as_ref().ok_or("NSS_Init not loaded")?;
        let result = unsafe { nss_init(c_profile.as_ptr()) };
        if result != 0 {
            return Err(format!("Failed to initialize NSS: {}", result));
        }

        let get_slot = self.pk11_get_internal_key_slot.as_ref().ok_or("PK11_GetInternalKeySlot not loaded")?;
        let slot = unsafe { get_slot() };
        if slot.is_null() {
            return Err("Failed to get internal key slot".into());
        }

        let need_login = self.pk11_need_login.as_ref().ok_or("PK11_NeedLogin not loaded")?;
        if unsafe { need_login(slot) } != 0 {
            if let Some(password) = master_password {
                let c_password = CString::new(password).map_err(|e| e.to_string())?;
                let check_pw = self.pk11_check_user_password.as_ref().ok_or("PK11_CheckUserPassword not loaded")?;
                if unsafe { check_pw(slot, c_password.as_ptr()) } != 0 {
                    let free_slot = self.pk11_free_slot.as_ref().ok_or("PK11_FreeSlot not loaded")?;
                    unsafe { free_slot(slot) };
                    return Err("Incorrect master password".into());
                }
            } else {
                let free_slot = self.pk11_free_slot.as_ref().ok_or("PK11_FreeSlot not loaded")?;
                unsafe { free_slot(slot) };
                return Err("Master password required but not provided".into());
            }
        }

        let free_slot = self.pk11_free_slot.as_ref().ok_or("PK11_FreeSlot not loaded")?;
        unsafe { free_slot(slot) };
        Ok(())
    }

    pub fn shutdown(&self) -> Result<(), String> {
        let shutdown = self.nss_shutdown.as_ref().ok_or("NSS_Shutdown not loaded")?;
        let result = unsafe { shutdown() };
        if result != 0 {
            return Err(format!("Failed to shutdown NSS: {}", result));
        }
        Ok(())
    }

    pub fn decrypt(&self, data: &str) -> Result<String, String> {
        let decoded = general_purpose::STANDARD.decode(data).map_err(|e| format!("Base64 decode error: {}", e))?;

        let mut in_item = SECItem { type_: 0, data: decoded.as_ptr() as *mut u8, len: decoded.len() as c_uint };
        let mut out_item = SECItem { type_: 0, data: ptr::null_mut(), len: 0 };

        let decrypt = self.pk11sdr_decrypt.as_ref().ok_or("PK11SDR_Decrypt not loaded")?;
        if unsafe { decrypt(&mut in_item, &mut out_item, ptr::null_mut()) } != 0 {
            return Err("Decryption failed".into());
        }

        let decrypted_bytes = unsafe { std::slice::from_raw_parts(out_item.data, out_item.len as usize) };
        let decrypted = String::from_utf8(decrypted_bytes.to_vec()).map_err(|e| format!("UTF-8 decode error: {}", e))?;
        
        let zfree = self.secitem_zfree_item.as_ref().ok_or("SECITEM_ZfreeItem not loaded")?;
        unsafe { zfree(&mut out_item, 0) };
        Ok(decrypted)
    }
}

impl Drop for NSSDecryptor {
    fn drop(&mut self) {
        if let Some(shutdown) = &self.nss_shutdown {
            unsafe { shutdown() };
        }
    }
}