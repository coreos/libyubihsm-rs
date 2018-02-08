use errors::*;
use types::*;
use session::Session;

use yubihsm_sys::{self, yh_algorithm, yh_connector, yh_session, YH_CONTEXT_LEN,
                  YH_MAX_ALGORITHM_COUNT};

use std::cell::Cell;
use std::ffi::CString;
use std::ptr;

#[derive(Clone, Debug)]
pub struct Connector {
    this: Cell<*mut yh_connector>,
    connected: Cell<bool>,
}

impl Connector {
    pub(crate) fn new(this: *mut yh_connector) -> Connector {
        Connector {
            this: Cell::new(this),
            connected: Cell::new(false),
        }
    }

    pub fn connect(&self) -> Result<()> {
        let mut this = self.this.get();

        unsafe {
            let ret = ReturnCode::from(yubihsm_sys::yh_connect_best(&mut this, 1, ptr::null_mut()));

            if ret != ReturnCode::Success {
                bail!(format!("failed to connect: {}", ret));
            }
        }

        self.this.set(this);
        self.connected.set(true);

        Ok(())
    }

    /// Create a new session with the specified AuthKey and password, and authenticate it.
    pub fn create_session_from_password(
        &self,
        auth_key_id: u16,
        password: &str,
        recreate_session: bool,
    ) -> Result<Session> {
        if !self.connected.get() {
            bail!("tried to use unconnected connector");
        }

        let mut session_ptr: *mut yh_session = ptr::null_mut();
        let mut context: Vec<u8> = Vec::with_capacity(YH_CONTEXT_LEN as usize);

        let password_c = CString::new(password)?;
        let password_bytes = password_c.as_bytes();

        unsafe {
            let mut ret = ReturnCode::from(yubihsm_sys::yh_create_session_derived(
                self.this.get(),
                auth_key_id,
                password_bytes.as_ptr(),
                password_bytes.len(),
                recreate_session,
                context.as_mut_ptr(),
                YH_CONTEXT_LEN as usize,
                &mut session_ptr,
            ));

            if ret != ReturnCode::Success {
                bail!(format!("failed to create session: {}", ret));
            }

            context.set_len(YH_CONTEXT_LEN as usize);

            ret = ReturnCode::from(yubihsm_sys::yh_authenticate_session(
                session_ptr,
                context.as_mut_ptr(),
                YH_CONTEXT_LEN as usize,
            ));

            if ret != ReturnCode::Success {
                bail!(format!("failed to authenticate session: {}", ret));
            }
        }

        Ok(Session::new(session_ptr))
    }

    pub fn get_device_info(&self) -> Result<DeviceInfo> {
        let mut major: u8 = 0;
        let mut minor: u8 = 0;
        let mut patch: u8 = 0;
        let mut serial: u32 = 0;
        let mut log_total: u8 = 0;
        let mut log_used: u8 = 0;
        let mut algorithms: Vec<yh_algorithm> = Vec::with_capacity(YH_MAX_ALGORITHM_COUNT as usize);
        let mut algorithm_count = YH_MAX_ALGORITHM_COUNT as usize;

        unsafe {
            let ret = ReturnCode::from(yubihsm_sys::yh_util_get_device_info(
                self.this.get(),
                &mut major,
                &mut minor,
                &mut patch,
                &mut serial,
                &mut log_total,
                &mut log_used,
                algorithms.as_mut_ptr(),
                &mut algorithm_count,
            ));

            if ret != ReturnCode::Success {
                bail!(format!("failed to get device info: {}", ret));
            }

            algorithms.set_len(algorithm_count);
        }

        Ok(DeviceInfo {
            major_version: major,
            minor_version: minor,
            patch_version: patch,
            serial: serial,
            log_capacity: log_total,
            log_used: log_used,
            algorithms: algorithms
                .into_iter()
                .map(Algorithm::from)
                .collect::<Vec<_>>(),
        })
    }
}

impl Drop for Connector {
    fn drop(&mut self) {
        if self.connected.get() {
            unsafe { yubihsm_sys::yh_disconnect(self.this.get()); }
        }
    }
}
