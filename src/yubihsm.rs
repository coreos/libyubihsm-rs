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
