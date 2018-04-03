// Copyright 2018 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use types::*;
use session::Session;

use failure::Error;
use yubihsm_sys::{self, yh_algorithm, yh_connector, yh_connector_option,
                  yh_connector_option_YH_CONNECTOR_HTTPS_CA,
                  yh_connector_option_YH_CONNECTOR_PROXY_SERVER, yh_session,
                  YH_CONTEXT_LEN, YH_MAX_ALGORITHM_COUNT};

use std::ffi::CString;
use std::ops::Deref;
use std::os::raw::c_void;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};

#[derive(Debug)]
struct ConnectorPtr(AtomicPtr<yh_connector>);

impl Drop for ConnectorPtr {
    fn drop(&mut self) {
        unsafe {
            yubihsm_sys::yh_disconnect(self.0.load(Ordering::Relaxed));
        }
    }
}

impl Deref for ConnectorPtr {
    type Target = AtomicPtr<yh_connector>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct ConnectorBuilder {
    https_ca: Option<String>,
    proxy_server: Option<String>,
}

impl ConnectorBuilder {
    pub(crate) fn new() -> ConnectorBuilder {
        ConnectorBuilder {
            https_ca: None,
            proxy_server: None,
        }
    }

    pub fn with_https_ca(mut self, ca_file: String) -> ConnectorBuilder {
        self.https_ca = Some(ca_file);
        self
    }

    pub fn with_proxy_server(mut self, proxy_server: String) -> ConnectorBuilder {
        self.proxy_server = Some(proxy_server);
        self
    }

    pub fn connect(self, url: &str) -> Result<Connector, Error> {
        let url_c = CString::new(url)?;
        let mut connector = Connector::new(url_c)?;

        if let Some(https_ca) = self.https_ca {
            connector.set_string_option(yh_connector_option_YH_CONNECTOR_HTTPS_CA, &https_ca)?;
        }

        if let Some(proxy_server) = self.proxy_server {
            connector.set_string_option(yh_connector_option_YH_CONNECTOR_PROXY_SERVER, &proxy_server)?;
        }

        connector.connect()?;
        Ok(connector)
    }
}

#[derive(Clone, Debug)]
pub struct Connector {
    this: Arc<ConnectorPtr>,
}

impl Connector {
    fn new(url: CString) -> Result<Connector, Error> {
        let mut connector_ptr: *mut yh_connector = ptr::null_mut();

        unsafe {
            let ret = ReturnCode::from(yubihsm_sys::yh_init_connector(
                url.as_ptr(),
                &mut connector_ptr,
            ));

            if ret != ReturnCode::Success {
                bail!("couldn't create connector: {}", ret);
            }
        }

        Ok(Connector {
            this: Arc::new(ConnectorPtr(AtomicPtr::new(connector_ptr))),
        })
    }

    fn connect(&mut self) -> Result<(), Error> {
        let mut this = self.this.load(Ordering::Relaxed);

        unsafe {
            let ret = ReturnCode::from(yubihsm_sys::yh_connect_best(&mut this, 1, ptr::null_mut()));

            if ret != ReturnCode::Success {
                bail!("failed to connect: {}", ret);
            }
        }

        Ok(())
    }

    fn set_string_option(&mut self, option: yh_connector_option, value: &str) -> Result<(), Error> {
        let this = self.this.load(Ordering::Relaxed);
        let value_c = CString::new(value)?;

        unsafe {
            let ret = ReturnCode::from(yubihsm_sys::yh_set_connector_option(
                this,
                option,
                value_c.as_ptr() as *const c_void,
            ));

            if ret != ReturnCode::Success {
                bail!("failed to set option: {}", ret);
            }
        }

        Ok(())
    }

    /// Create a new session with the specified AuthKey and password, and authenticate it.
    pub fn create_session_from_password(
        &self,
        auth_key_id: u16,
        password: &str,
        recreate_session: bool,
    ) -> Result<Session, Error> {
        let mut session_ptr: *mut yh_session = ptr::null_mut();
        let mut context: Vec<u8> = Vec::with_capacity(YH_CONTEXT_LEN as usize);

        let password_c = CString::new(password)?;
        let password_bytes = password_c.as_bytes();

        unsafe {
            let mut ret = ReturnCode::from(yubihsm_sys::yh_create_session_derived(
                self.this.load(Ordering::Relaxed),
                auth_key_id,
                password_bytes.as_ptr(),
                password_bytes.len(),
                recreate_session,
                context.as_mut_ptr(),
                YH_CONTEXT_LEN as usize,
                &mut session_ptr,
            ));

            if ret != ReturnCode::Success {
                bail!("failed to create session: {}", ret);
            }

            context.set_len(YH_CONTEXT_LEN as usize);

            ret = ReturnCode::from(yubihsm_sys::yh_authenticate_session(
                session_ptr,
                context.as_mut_ptr(),
                YH_CONTEXT_LEN as usize,
            ));

            if ret != ReturnCode::Success {
                bail!("failed to authenticate session: {}", ret);
            }
        }

        Ok(Session::new(session_ptr))
    }

    pub fn get_device_info(&self) -> Result<DeviceInfo, Error> {
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
                self.this.load(Ordering::Relaxed),
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
                bail!("failed to get device info: {}", ret);
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
