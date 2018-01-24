use yubihsm_sys::*;

use std::ffi::CStr;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReturnCode {
    Success,
    Memory,
    InitError,
    NetError,
    ConnectorNotFound,
    InvalidParams,
    WrongLength,
    BufferTooSmall,
    CryptogramMismatch,
    AuthSessionError,
    MacMismatch,
    DeviceOk,
    DeviceInvCommand,
    DeviceInvData,
    DeviceInvSession,
    DeviceAuthFail,
    DeviceSessionsFull,
    DeviceSessionFailed,
    DeviceStorageFailed,
    DeviceWrongLength,
    DeviceInvPermission,
    DeviceLogFull,
    DeviceObjNotFound,
    DeviceIdIllegal,
    DeviceInvalidOtp,
    DeviceDemoMode,
    DeviceCmdUnexecuted,
    GenericError,
    DeviceObjectExists,
    ConnectorError,
}

#[allow(non_upper_case_globals)]
impl From<yh_rc> for ReturnCode {
    fn from(rc: yh_rc) -> Self {
        match rc {
            yh_rc_YHR_SUCCESS => ReturnCode::Success,
            yh_rc_YHR_MEMORY => ReturnCode::Memory,
            yh_rc_YHR_INIT_ERROR => ReturnCode::InitError,
            yh_rc_YHR_NET_ERROR => ReturnCode::NetError,
            yh_rc_YHR_CONNECTOR_NOT_FOUND => ReturnCode::ConnectorNotFound,
            yh_rc_YHR_INVALID_PARAMS => ReturnCode::InvalidParams,
            yh_rc_YHR_WRONG_LENGTH => ReturnCode::WrongLength,
            yh_rc_YHR_BUFFER_TOO_SMALL => ReturnCode::BufferTooSmall,
            yh_rc_YHR_CRYPTOGRAM_MISMATCH => ReturnCode::CryptogramMismatch,
            yh_rc_YHR_AUTH_SESSION_ERROR => ReturnCode::AuthSessionError,
            yh_rc_YHR_MAC_MISMATCH => ReturnCode::MacMismatch,
            yh_rc_YHR_DEVICE_OK => ReturnCode::DeviceOk,
            yh_rc_YHR_DEVICE_INV_COMMAND => ReturnCode::DeviceInvCommand,
            yh_rc_YHR_DEVICE_INV_DATA => ReturnCode::DeviceInvData,
            yh_rc_YHR_DEVICE_INV_SESSION => ReturnCode::DeviceInvSession,
            yh_rc_YHR_DEVICE_AUTH_FAIL => ReturnCode::DeviceAuthFail,
            yh_rc_YHR_DEVICE_SESSIONS_FULL => ReturnCode::DeviceSessionsFull,
            yh_rc_YHR_DEVICE_SESSION_FAILED => ReturnCode::DeviceSessionFailed,
            yh_rc_YHR_DEVICE_STORAGE_FAILED => ReturnCode::DeviceStorageFailed,
            yh_rc_YHR_DEVICE_WRONG_LENGTH => ReturnCode::DeviceWrongLength,
            yh_rc_YHR_DEVICE_INV_PERMISSION => ReturnCode::DeviceInvPermission,
            yh_rc_YHR_DEVICE_LOG_FULL => ReturnCode::DeviceLogFull,
            yh_rc_YHR_DEVICE_OBJ_NOT_FOUND => ReturnCode::DeviceObjNotFound,
            yh_rc_YHR_DEVICE_ID_ILLEGAL => ReturnCode::DeviceIdIllegal,
            yh_rc_YHR_DEVICE_INVALID_OTP => ReturnCode::DeviceInvalidOtp,
            yh_rc_YHR_DEVICE_DEMO_MODE => ReturnCode::DeviceDemoMode,
            yh_rc_YHR_DEVICE_CMD_UNEXECUTED => ReturnCode::DeviceCmdUnexecuted,
            yh_rc_YHR_GENERIC_ERROR => ReturnCode::GenericError,
            yh_rc_YHR_DEVICE_OBJECT_EXISTS => ReturnCode::DeviceObjectExists,
            yh_rc_YHR_CONNECTOR_ERROR => ReturnCode::ConnectorError,
            _ => panic!(format!("unexpected return code: {}", rc)),
        }
    }
}

#[allow(non_upper_case_globals)]
impl From<ReturnCode> for yh_rc {
    fn from(rc: ReturnCode) -> Self {
        match rc {
            ReturnCode::Success => yh_rc_YHR_SUCCESS,
            ReturnCode::Memory => yh_rc_YHR_MEMORY,
            ReturnCode::InitError => yh_rc_YHR_INIT_ERROR,
            ReturnCode::NetError => yh_rc_YHR_NET_ERROR,
            ReturnCode::ConnectorNotFound => yh_rc_YHR_CONNECTOR_NOT_FOUND,
            ReturnCode::InvalidParams => yh_rc_YHR_INVALID_PARAMS,
            ReturnCode::WrongLength => yh_rc_YHR_WRONG_LENGTH,
            ReturnCode::BufferTooSmall => yh_rc_YHR_BUFFER_TOO_SMALL,
            ReturnCode::CryptogramMismatch => yh_rc_YHR_CRYPTOGRAM_MISMATCH,
            ReturnCode::AuthSessionError => yh_rc_YHR_AUTH_SESSION_ERROR,
            ReturnCode::MacMismatch => yh_rc_YHR_MAC_MISMATCH,
            ReturnCode::DeviceOk => yh_rc_YHR_DEVICE_OK,
            ReturnCode::DeviceInvCommand => yh_rc_YHR_DEVICE_INV_COMMAND,
            ReturnCode::DeviceInvData => yh_rc_YHR_DEVICE_INV_DATA,
            ReturnCode::DeviceInvSession => yh_rc_YHR_DEVICE_INV_SESSION,
            ReturnCode::DeviceAuthFail => yh_rc_YHR_DEVICE_AUTH_FAIL,
            ReturnCode::DeviceSessionsFull => yh_rc_YHR_DEVICE_SESSIONS_FULL,
            ReturnCode::DeviceSessionFailed => yh_rc_YHR_DEVICE_SESSION_FAILED,
            ReturnCode::DeviceStorageFailed => yh_rc_YHR_DEVICE_STORAGE_FAILED,
            ReturnCode::DeviceWrongLength => yh_rc_YHR_DEVICE_WRONG_LENGTH,
            ReturnCode::DeviceInvPermission => yh_rc_YHR_DEVICE_INV_PERMISSION,
            ReturnCode::DeviceLogFull => yh_rc_YHR_DEVICE_LOG_FULL,
            ReturnCode::DeviceObjNotFound => yh_rc_YHR_DEVICE_OBJ_NOT_FOUND,
            ReturnCode::DeviceIdIllegal => yh_rc_YHR_DEVICE_ID_ILLEGAL,
            ReturnCode::DeviceInvalidOtp => yh_rc_YHR_DEVICE_INVALID_OTP,
            ReturnCode::DeviceDemoMode => yh_rc_YHR_DEVICE_DEMO_MODE,
            ReturnCode::DeviceCmdUnexecuted => yh_rc_YHR_DEVICE_CMD_UNEXECUTED,
            ReturnCode::GenericError => yh_rc_YHR_GENERIC_ERROR,
            ReturnCode::DeviceObjectExists => yh_rc_YHR_DEVICE_OBJECT_EXISTS,
            ReturnCode::ConnectorError => yh_rc_YHR_CONNECTOR_ERROR,
        }
    }
}

impl Display for ReturnCode {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        unsafe {
            let error = CStr::from_ptr(yh_strerror(yh_rc::from(*self)));
            write!(f, "{}", error.to_string_lossy())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ObjectType {
    Asymmetric,
    AuthKey,
    HmacKey,
    Opaque,
    OtpAeadKey,
    Public,
    Template,
    WrapKey,
}

#[allow(non_upper_case_globals)]
impl From<yh_object_type> for ObjectType {
    fn from(obj: yh_object_type) -> Self {
        match obj {
            yh_object_type_YH_ASYMMETRIC => ObjectType::Asymmetric,
            yh_object_type_YH_AUTHKEY => ObjectType::AuthKey,
            yh_object_type_YH_HMACKEY => ObjectType::HmacKey,
            yh_object_type_YH_OPAQUE => ObjectType::Opaque,
            yh_object_type_YH_OTP_AEAD_KEY => ObjectType::OtpAeadKey,
            yh_object_type_YH_PUBLIC => ObjectType::Public,
            yh_object_type_YH_TEMPLATE => ObjectType::Template,
            yh_object_type_YH_WRAPKEY => ObjectType::WrapKey,
            _ => panic!(format!("unexpected object type: {}", obj)),
        }
    }
}
