use connector::ConnectorBuilder;
use types::*;

use failure::Error;
use yubihsm_sys::{self, yh_rc, yh_rc_YHR_SUCCESS};

use std::sync::{Once, ONCE_INIT};
use std::marker::PhantomData;
use std::ptr;

static LIBYUBIHSM_INIT: Once = ONCE_INIT;

/// Primary library entrypoint. Used to create `Connector`s, which can in turn be used to create
/// sessions.
#[derive(Copy, Clone, Debug)]
pub struct Yubihsm {
    marker: PhantomData<()>,
}

impl Yubihsm {
    pub fn new() -> Result<Self, Error> {
        let mut ret: yh_rc = yh_rc_YHR_SUCCESS;

        LIBYUBIHSM_INIT.call_once(|| unsafe {
            ret = yubihsm_sys::yh_init();
        });

        if ret != yh_rc_YHR_SUCCESS {
            bail!("yh_init returned {}", ret);
        }

        Ok(Yubihsm {
            marker: PhantomData,
        })
    }

    pub fn connector(&self) -> ConnectorBuilder {
        ConnectorBuilder::new()
    }

    pub fn verify_logs<T: AsRef<[LogEntry]>>(
        &self,
        logs: T,
        previous_log: Option<LogEntry>,
    ) -> bool {
        let mut logs = Vec::from(logs.as_ref())
            .into_iter()
            .map(yubihsm_sys::yh_log_entry::from)
            .collect::<Vec<_>>();
        let previous_log = match previous_log {
            Some(log) => &mut log.clone().into(),
            None => ptr::null_mut(),
        };

        unsafe { yubihsm_sys::yh_verify_logs(logs.as_mut_ptr(), logs.len(), previous_log) }
    }
}
