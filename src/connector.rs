use errors::*;
use session::Session;

use yubihsm_sys::{self, yh_connector, yh_session, yh_rc_YHR_SUCCESS, YH_CONTEXT_LEN};

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
            let ret = yubihsm_sys::yh_connect_best(&mut this, 1, ptr::null_mut());

            if ret != yh_rc_YHR_SUCCESS {
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
            let mut ret = yubihsm_sys::yh_create_session_derived(
                self.this.get(),
                auth_key_id,
                password_bytes.as_ptr(),
                password_bytes.len(),
                recreate_session,
                context.as_mut_ptr(),
                YH_CONTEXT_LEN as usize,
                &mut session_ptr,
            );

            if ret != yh_rc_YHR_SUCCESS {
                bail!(format!("failed to create session: {}", ret));
            }

            ret = yubihsm_sys::yh_authenticate_session(
                session_ptr,
                context.as_mut_ptr(),
                YH_CONTEXT_LEN as usize,
            );

            if ret != yh_rc_YHR_SUCCESS {
                bail!(format!("failed to authenticate session: {}", ret));
            }
        }

        Ok(Session::new(session_ptr))
    }
}
