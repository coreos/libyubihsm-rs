use errors::*;
use connector;

use yubihsm_sys::{self, yh_connector, yh_rc, yh_rc_YHR_SUCCESS};

use std::ffi::CString;
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
    pub fn new() -> Result<Self> {
        let mut ret: yh_rc = yh_rc_YHR_SUCCESS;

        LIBYUBIHSM_INIT.call_once(|| unsafe {
            ret = yubihsm_sys::yh_init();
        });

        if ret != yh_rc_YHR_SUCCESS {
            bail!(format!("yh_init returned {}", ret));
        }

        Ok(Yubihsm {
            marker: PhantomData,
        })
    }

    pub fn create_connector(url: &str) -> Result<connector::Connector> {
        let url_c = CString::new(url)?;
        let mut connector_ptr: *mut yh_connector = ptr::null_mut();

        unsafe {
            let ret = yubihsm_sys::yh_init_connector(url_c.as_ptr(), &mut connector_ptr);

            if ret != yh_rc_YHR_SUCCESS {
                bail!(format!("couldn't create connector: {}", ret));
            }
        }

        Ok(connector::Connector {
            this: connector_ptr,
        })
    }
}
