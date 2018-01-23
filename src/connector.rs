use errors::*;

use yubihsm_sys::{self, yh_connector, yh_rc, yh_rc_YHR_SUCCESS};

#[derive(Copy, Clone, Debug)]
pub struct Connector {
    pub(crate) this: *mut yh_connector,
}
