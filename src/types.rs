use failure::Error;
use yubihsm_sys::*;

use std::ffi::{CStr, CString};
use std::fmt::{Display, Formatter};
use std::os::raw::c_char;
use std::ptr;

/// Wrapper struct for "encoded" Domains. This is the type expected by libyubihsm functions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct DomainParam(pub(crate) u16);
/// Wrapper struct for a single Domain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Domain(pub(crate) u8);

impl Domain {
    pub fn new(domain: u8) -> Result<Domain, Error> {
        if domain < 1 || domain > 16 {
            bail!("invalid domain");
        }

        Ok(Domain(domain))
    }
}

impl From<Domain> for String {
    fn from(dom: Domain) -> Self {
        format!("{}", dom.0)
    }
}

impl From<Domain> for DomainParam {
    fn from(dom: Domain) -> Self {
        let mut out: u16 = 0;
        let dom_str = CString::new(format!("{}", dom.0))
            .unwrap_or_else(|_| panic!("couldn't make CString from Domain"));

        unsafe {
            let ret = ReturnCode::from(yh_parse_domains(dom_str.as_ptr(), &mut out));

            if ret != ReturnCode::Success {
                panic!("parse_domains failed: {}", ret);
            }
        }

        DomainParam(out)
    }
}

impl<T> From<T> for DomainParam
where
    T: AsRef<[Domain]> + IntoIterator<Item = Domain>,
{
    fn from(doms: T) -> Self {
        let mut out: u16 = 0;
        let joined_doms = doms.into_iter()
            .map(String::from)
            .collect::<Vec<String>>()
            .join(",");

        let dom_str = CString::new(joined_doms)
            .unwrap_or_else(|_| panic!("couldn't make CString from Domains"));

        unsafe {
            let ret = ReturnCode::from(yh_parse_domains(dom_str.as_ptr(), &mut out));

            if ret != ReturnCode::Success {
                panic!("parse_domains failed: {}", ret);
            }
        }

        DomainParam(out)
    }
}

impl From<DomainParam> for Vec<Domain> {
    fn from(dom_param: DomainParam) -> Self {
        let cstring_contents: Vec<u8> = Vec::with_capacity(40);

        unsafe {
            let raw_cstring = CString::from_vec_unchecked(cstring_contents).into_raw();
            let ret = ReturnCode::from(yh_domains_to_string(dom_param.0, raw_cstring, 40));

            if ret != ReturnCode::Success {
                panic!("domains_to_string failed: {}", ret);
            }

            let cstring = CString::from_raw(raw_cstring);

            // If libyubihsm is giving us back invalid domains, there's not much we can do about
            // it, so unwrapping is okay here.
            cstring
                .to_string_lossy()
                .split(':')
                .map(|d| d.parse::<u8>().unwrap())
                .map(|d| Domain::new(d).unwrap())
                .collect()
        }
    }
}

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
            _ => panic!("unexpected return code: {}", rc),
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
        let error_name = match *self {
            ReturnCode::Success => "Success",
            ReturnCode::Memory => "Memory",
            ReturnCode::InitError => "InitError",
            ReturnCode::NetError => "NetError",
            ReturnCode::ConnectorNotFound => "ConnectorNotFound",
            ReturnCode::InvalidParams => "InvalidParams",
            ReturnCode::WrongLength => "WrongLength",
            ReturnCode::BufferTooSmall => "BufferTooSmall",
            ReturnCode::CryptogramMismatch => "CryptogramMismatch",
            ReturnCode::AuthSessionError => "AuthSessionError",
            ReturnCode::MacMismatch => "MacMismatch",
            ReturnCode::DeviceOk => "DeviceOk",
            ReturnCode::DeviceInvCommand => "DeviceInvCommand",
            ReturnCode::DeviceInvData => "DeviceInvData",
            ReturnCode::DeviceInvSession => "DeviceInvSession",
            ReturnCode::DeviceAuthFail => "DeviceAuthFail",
            ReturnCode::DeviceSessionsFull => "DeviceSessionsFull",
            ReturnCode::DeviceSessionFailed => "DeviceSessionFailed",
            ReturnCode::DeviceStorageFailed => "DeviceStorageFailed",
            ReturnCode::DeviceWrongLength => "DeviceWrongLength",
            ReturnCode::DeviceInvPermission => "DeviceInvPermission",
            ReturnCode::DeviceLogFull => "DeviceLogFull",
            ReturnCode::DeviceObjNotFound => "DeviceObjNotFound",
            ReturnCode::DeviceIdIllegal => "DeviceIdIllegal",
            ReturnCode::DeviceInvalidOtp => "DeviceInvalidOtp",
            ReturnCode::DeviceDemoMode => "DeviceDemoMode",
            ReturnCode::DeviceCmdUnexecuted => "DeviceCmdUnexecuted",
            ReturnCode::GenericError => "GenericError",
            ReturnCode::DeviceObjectExists => "DeviceObjectExists",
            ReturnCode::ConnectorError => "ConnectorError",
        };

        unsafe {
            let error = CStr::from_ptr(yh_strerror(yh_rc::from(*self)));
            write!(f, "{} (ReturnCode::{})", error.to_string_lossy(), error_name)
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
            _ => panic!("unexpected object type: {}", obj),
        }
    }
}

#[allow(non_upper_case_globals)]
impl From<ObjectType> for yh_object_type {
    fn from(obj: ObjectType) -> Self {
        match obj {
            ObjectType::Asymmetric => yh_object_type_YH_ASYMMETRIC,
            ObjectType::AuthKey => yh_object_type_YH_AUTHKEY,
            ObjectType::HmacKey => yh_object_type_YH_HMACKEY,
            ObjectType::Opaque => yh_object_type_YH_OPAQUE,
            ObjectType::OtpAeadKey => yh_object_type_YH_OTP_AEAD_KEY,
            ObjectType::Public => yh_object_type_YH_PUBLIC,
            ObjectType::Template => yh_object_type_YH_TEMPLATE,
            ObjectType::WrapKey => yh_object_type_YH_WRAPKEY,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Algorithm {
    RsaPkcs1Sha1,
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPssSha1,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcP256,
    EcP384,
    EcP521,
    EcK256,
    EcBp256,
    EcBp384,
    EcBp512,
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    EcEcdsaSha1,
    EcEcdh,
    RsaOaepSha1,
    RsaOaepSha256,
    RsaOaepSha384,
    RsaOaepSha512,
    Aes128CcmWrap,
    OpaqueData,
    OpaqueX509Cert,
    Mgf1Sha1,
    Mgf1Sha256,
    Mgf1Sha384,
    Mgf1Sha512,
    TemplSsh,
    YubicoOtpAes128,
    YubicoAesAuth,
    YubicoOtpAes192,
    YubicoOtpAes256,
    Aes192CcmWrap,
    Aes256CcmWrap,
    EcEcdsaSha256,
    EcEcdsaSha384,
    EcEcdsaSha512,
    EcEd25519,
    EcP224,
}

#[allow(non_upper_case_globals)]
impl From<yh_algorithm> for Algorithm {
    fn from(alg: yh_object_type) -> Self {
        match alg {
            yh_algorithm_YH_ALGO_RSA_PKCS1_SHA1 => Algorithm::RsaPkcs1Sha1,
            yh_algorithm_YH_ALGO_RSA_PKCS1_SHA256 => Algorithm::RsaPkcs1Sha256,
            yh_algorithm_YH_ALGO_RSA_PKCS1_SHA384 => Algorithm::RsaPkcs1Sha384,
            yh_algorithm_YH_ALGO_RSA_PKCS1_SHA512 => Algorithm::RsaPkcs1Sha512,
            yh_algorithm_YH_ALGO_RSA_PSS_SHA1 => Algorithm::RsaPssSha1,
            yh_algorithm_YH_ALGO_RSA_PSS_SHA256 => Algorithm::RsaPssSha256,
            yh_algorithm_YH_ALGO_RSA_PSS_SHA384 => Algorithm::RsaPssSha384,
            yh_algorithm_YH_ALGO_RSA_PSS_SHA512 => Algorithm::RsaPssSha512,
            yh_algorithm_YH_ALGO_RSA_2048 => Algorithm::Rsa2048,
            yh_algorithm_YH_ALGO_RSA_3072 => Algorithm::Rsa3072,
            yh_algorithm_YH_ALGO_RSA_4096 => Algorithm::Rsa4096,
            yh_algorithm_YH_ALGO_EC_P224 => Algorithm::EcP224,
            yh_algorithm_YH_ALGO_EC_P256 => Algorithm::EcP256,
            yh_algorithm_YH_ALGO_EC_P384 => Algorithm::EcP384,
            yh_algorithm_YH_ALGO_EC_P521 => Algorithm::EcP521,
            yh_algorithm_YH_ALGO_EC_K256 => Algorithm::EcK256,
            yh_algorithm_YH_ALGO_EC_BP256 => Algorithm::EcBp256,
            yh_algorithm_YH_ALGO_EC_BP384 => Algorithm::EcBp384,
            yh_algorithm_YH_ALGO_EC_BP512 => Algorithm::EcBp512,
            yh_algorithm_YH_ALGO_HMAC_SHA1 => Algorithm::HmacSha1,
            yh_algorithm_YH_ALGO_HMAC_SHA256 => Algorithm::HmacSha256,
            yh_algorithm_YH_ALGO_HMAC_SHA384 => Algorithm::HmacSha384,
            yh_algorithm_YH_ALGO_HMAC_SHA512 => Algorithm::HmacSha512,
            yh_algorithm_YH_ALGO_EC_ECDSA_SHA1 => Algorithm::EcEcdsaSha1,
            yh_algorithm_YH_ALGO_EC_ECDSA_SHA256 => Algorithm::EcEcdsaSha256,
            yh_algorithm_YH_ALGO_EC_ECDSA_SHA384 => Algorithm::EcEcdsaSha384,
            yh_algorithm_YH_ALGO_EC_ECDSA_SHA512 => Algorithm::EcEcdsaSha512,
            yh_algorithm_YH_ALGO_EC_ECDH => Algorithm::EcEcdh,
            yh_algorithm_YH_ALGO_RSA_OAEP_SHA1 => Algorithm::RsaOaepSha1,
            yh_algorithm_YH_ALGO_RSA_OAEP_SHA256 => Algorithm::RsaOaepSha256,
            yh_algorithm_YH_ALGO_RSA_OAEP_SHA384 => Algorithm::RsaOaepSha384,
            yh_algorithm_YH_ALGO_RSA_OAEP_SHA512 => Algorithm::RsaOaepSha512,
            yh_algorithm_YH_ALGO_AES128_CCM_WRAP => Algorithm::Aes128CcmWrap,
            yh_algorithm_YH_ALGO_AES192_CCM_WRAP => Algorithm::Aes192CcmWrap,
            yh_algorithm_YH_ALGO_AES256_CCM_WRAP => Algorithm::Aes256CcmWrap,
            yh_algorithm_YH_ALGO_OPAQUE_DATA => Algorithm::OpaqueData,
            yh_algorithm_YH_ALGO_OPAQUE_X509_CERT => Algorithm::OpaqueX509Cert,
            yh_algorithm_YH_ALGO_MGF1_SHA1 => Algorithm::Mgf1Sha1,
            yh_algorithm_YH_ALGO_MGF1_SHA256 => Algorithm::Mgf1Sha256,
            yh_algorithm_YH_ALGO_MGF1_SHA384 => Algorithm::Mgf1Sha384,
            yh_algorithm_YH_ALGO_MGF1_SHA512 => Algorithm::Mgf1Sha512,
            yh_algorithm_YH_ALGO_TEMPL_SSH => Algorithm::TemplSsh,
            yh_algorithm_YH_ALGO_YUBICO_OTP_AES128 => Algorithm::YubicoOtpAes128,
            yh_algorithm_YH_ALGO_YUBICO_OTP_AES192 => Algorithm::YubicoOtpAes192,
            yh_algorithm_YH_ALGO_YUBICO_OTP_AES256 => Algorithm::YubicoOtpAes256,
            yh_algorithm_YH_ALGO_YUBICO_AES_AUTH => Algorithm::YubicoAesAuth,
            yh_algorithm_YH_ALGO_EC_ED25519 => Algorithm::EcEd25519,
            _ => panic!("unexpected algorithm type: {}", alg),
        }
    }
}

#[allow(non_upper_case_globals)]
impl From<Algorithm> for yh_algorithm {
    fn from(alg: Algorithm) -> Self {
        match alg {
            Algorithm::RsaPkcs1Sha1 => yh_algorithm_YH_ALGO_RSA_PKCS1_SHA1,
            Algorithm::RsaPkcs1Sha256 => yh_algorithm_YH_ALGO_RSA_PKCS1_SHA256,
            Algorithm::RsaPkcs1Sha384 => yh_algorithm_YH_ALGO_RSA_PKCS1_SHA384,
            Algorithm::RsaPkcs1Sha512 => yh_algorithm_YH_ALGO_RSA_PKCS1_SHA512,
            Algorithm::RsaPssSha1 => yh_algorithm_YH_ALGO_RSA_PSS_SHA1,
            Algorithm::RsaPssSha256 => yh_algorithm_YH_ALGO_RSA_PSS_SHA256,
            Algorithm::RsaPssSha384 => yh_algorithm_YH_ALGO_RSA_PSS_SHA384,
            Algorithm::RsaPssSha512 => yh_algorithm_YH_ALGO_RSA_PSS_SHA512,
            Algorithm::Rsa2048 => yh_algorithm_YH_ALGO_RSA_2048,
            Algorithm::Rsa3072 => yh_algorithm_YH_ALGO_RSA_3072,
            Algorithm::Rsa4096 => yh_algorithm_YH_ALGO_RSA_4096,
            Algorithm::EcP224 => yh_algorithm_YH_ALGO_EC_P224,
            Algorithm::EcP256 => yh_algorithm_YH_ALGO_EC_P256,
            Algorithm::EcP384 => yh_algorithm_YH_ALGO_EC_P384,
            Algorithm::EcP521 => yh_algorithm_YH_ALGO_EC_P521,
            Algorithm::EcK256 => yh_algorithm_YH_ALGO_EC_K256,
            Algorithm::EcBp256 => yh_algorithm_YH_ALGO_EC_BP256,
            Algorithm::EcBp384 => yh_algorithm_YH_ALGO_EC_BP384,
            Algorithm::EcBp512 => yh_algorithm_YH_ALGO_EC_BP512,
            Algorithm::HmacSha1 => yh_algorithm_YH_ALGO_HMAC_SHA1,
            Algorithm::HmacSha256 => yh_algorithm_YH_ALGO_HMAC_SHA256,
            Algorithm::HmacSha384 => yh_algorithm_YH_ALGO_HMAC_SHA384,
            Algorithm::HmacSha512 => yh_algorithm_YH_ALGO_HMAC_SHA512,
            Algorithm::EcEcdsaSha1 => yh_algorithm_YH_ALGO_EC_ECDSA_SHA1,
            Algorithm::EcEcdsaSha256 => yh_algorithm_YH_ALGO_EC_ECDSA_SHA256,
            Algorithm::EcEcdsaSha384 => yh_algorithm_YH_ALGO_EC_ECDSA_SHA384,
            Algorithm::EcEcdsaSha512 => yh_algorithm_YH_ALGO_EC_ECDSA_SHA512,
            Algorithm::EcEcdh => yh_algorithm_YH_ALGO_EC_ECDH,
            Algorithm::RsaOaepSha1 => yh_algorithm_YH_ALGO_RSA_OAEP_SHA1,
            Algorithm::RsaOaepSha256 => yh_algorithm_YH_ALGO_RSA_OAEP_SHA256,
            Algorithm::RsaOaepSha384 => yh_algorithm_YH_ALGO_RSA_OAEP_SHA384,
            Algorithm::RsaOaepSha512 => yh_algorithm_YH_ALGO_RSA_OAEP_SHA512,
            Algorithm::Aes128CcmWrap => yh_algorithm_YH_ALGO_AES128_CCM_WRAP,
            Algorithm::Aes192CcmWrap => yh_algorithm_YH_ALGO_AES192_CCM_WRAP,
            Algorithm::Aes256CcmWrap => yh_algorithm_YH_ALGO_AES256_CCM_WRAP,
            Algorithm::OpaqueData => yh_algorithm_YH_ALGO_OPAQUE_DATA,
            Algorithm::OpaqueX509Cert => yh_algorithm_YH_ALGO_OPAQUE_X509_CERT,
            Algorithm::Mgf1Sha1 => yh_algorithm_YH_ALGO_MGF1_SHA1,
            Algorithm::Mgf1Sha256 => yh_algorithm_YH_ALGO_MGF1_SHA256,
            Algorithm::Mgf1Sha384 => yh_algorithm_YH_ALGO_MGF1_SHA384,
            Algorithm::Mgf1Sha512 => yh_algorithm_YH_ALGO_MGF1_SHA512,
            Algorithm::TemplSsh => yh_algorithm_YH_ALGO_TEMPL_SSH,
            Algorithm::YubicoOtpAes128 => yh_algorithm_YH_ALGO_YUBICO_OTP_AES128,
            Algorithm::YubicoOtpAes192 => yh_algorithm_YH_ALGO_YUBICO_OTP_AES192,
            Algorithm::YubicoOtpAes256 => yh_algorithm_YH_ALGO_YUBICO_OTP_AES256,
            Algorithm::YubicoAesAuth => yh_algorithm_YH_ALGO_YUBICO_AES_AUTH,
            Algorithm::EcEd25519 => yh_algorithm_YH_ALGO_EC_ED25519,
        }
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        let mut string_ptr: *const c_char = ptr::null();

        unsafe {
            match ReturnCode::from(yh_algo_to_string((*self).into(), &mut string_ptr)) {
                ReturnCode::Success => {
                    let algo = CStr::from_ptr(string_ptr);
                    write!(f, "{}", algo.to_string_lossy())
                }
                _ => Err(::std::fmt::Error),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Capability {
    GetOpaque,
    PutOpaque,
    PutAuthKey,
    PutAsymmetric,
    AsymmetricGen,
    AsymmetricSignPkcs,
    AsymmetricSignPss,
    AsymmetricSignEcdsa,
    AsymmetricSignEddsa,
    AsymmetricDecryptPkcs,
    AsymmetricDecryptOaep,
    AsymmetricDecryptEcdh,
    ExportWrapped,
    ImportWrapped,
    PutWrapkey,
    GenerateWrapkey,
    ExportUnderWrap,
    PutOption,
    GetOption,
    GetRandomness,
    PutHmackey,
    HmackeyGenerate,
    HmacData,
    HmacVerify,
    Audit,
    SshCertify,
    GetTemplate,
    PutTemplate,
    Reset,
    OtpDecrypt,
    OtpAeadCreate,
    OtpAeadRandom,
    OtpAeadRewrapFrom,
    OtpAeadRewrapTo,
    Attest,
    PutOtpAeadKey,
    GenerateOtpAeadKey,
    WrapData,
    UnwrapData,
    DeleteOpaque,
    DeleteAuthkey,
    DeleteAsymmetric,
    DeleteWrapKey,
    DeleteHmacKey,
    DeleteTemplate,
    DeleteOtpAeadKey,
}

impl From<Capability> for String {
    fn from(cap: Capability) -> Self {
        match cap {
            Capability::GetOpaque => String::from("get_opaque"),
            Capability::PutOpaque => String::from("put_opaque"),
            Capability::PutAuthKey => String::from("put_authkey"),
            Capability::PutAsymmetric => String::from("put_asymmetric"),
            Capability::AsymmetricGen => String::from("asymmetric_gen"),
            Capability::AsymmetricSignPkcs => String::from("asymmetric_sign_pkcs"),
            Capability::AsymmetricSignPss => String::from("asymmetric_sign_pss"),
            Capability::AsymmetricSignEcdsa => String::from("asymmetric_sign_ecdsa"),
            Capability::AsymmetricSignEddsa => String::from("asymmetric_sign_eddsa"),
            Capability::AsymmetricDecryptPkcs => String::from("asymmetric_decrypt_pkcs"),
            Capability::AsymmetricDecryptOaep => String::from("asymmetric_decrypt_oaep"),
            Capability::AsymmetricDecryptEcdh => String::from("asymmetric_decrypt_ecdh"),
            Capability::ExportWrapped => String::from("export_wrapped"),
            Capability::ImportWrapped => String::from("import_wrapped"),
            Capability::PutWrapkey => String::from("put_wrapkey"),
            Capability::GenerateWrapkey => String::from("generate_wrapkey"),
            Capability::ExportUnderWrap => String::from("export_under_wrap"),
            Capability::PutOption => String::from("put_option"),
            Capability::GetOption => String::from("get_option"),
            Capability::GetRandomness => String::from("get_randomness"),
            Capability::PutHmackey => String::from("put_hmackey"),
            Capability::HmackeyGenerate => String::from("hmackey_generate"),
            Capability::HmacData => String::from("hmac_data"),
            Capability::HmacVerify => String::from("hmac_verify"),
            Capability::Audit => String::from("audit"),
            Capability::SshCertify => String::from("ssh_certify"),
            Capability::GetTemplate => String::from("get_template"),
            Capability::PutTemplate => String::from("put_template"),
            Capability::Reset => String::from("reset"),
            Capability::OtpDecrypt => String::from("otp_decrypt"),
            Capability::OtpAeadCreate => String::from("otp_aead_create"),
            Capability::OtpAeadRandom => String::from("otp_aead_random"),
            Capability::OtpAeadRewrapFrom => String::from("otp_aead_rewrap_from"),
            Capability::OtpAeadRewrapTo => String::from("otp_aead_rewrap_to"),
            Capability::Attest => String::from("attest"),
            Capability::PutOtpAeadKey => String::from("put_otp_aead_key"),
            Capability::GenerateOtpAeadKey => String::from("generate_otp_aead_key"),
            Capability::WrapData => String::from("wrap_data"),
            Capability::UnwrapData => String::from("unwrap_data"),
            Capability::DeleteOpaque => String::from("delete_opaque"),
            Capability::DeleteAuthkey => String::from("delete_authkey"),
            Capability::DeleteAsymmetric => String::from("delete_asymmetric"),
            Capability::DeleteWrapKey => String::from("delete_wrap_key"),
            Capability::DeleteHmacKey => String::from("delete_hmac_key"),
            Capability::DeleteTemplate => String::from("delete_template"),
            Capability::DeleteOtpAeadKey => String::from("delete_otp_aead_key"),
        }
    }
}

impl From<Capability> for yh_capabilities {
    fn from(cap: Capability) -> Self {
        let cap_str = CString::new(String::from(cap)).unwrap();
        let mut capability = yh_capabilities {
            capabilities: [0; 8],
        };

        unsafe {
            let ret = ReturnCode::from(yh_capabilities_to_num(cap_str.as_ptr(), &mut capability));

            if ret != ReturnCode::Success {
                panic!("capabilities_to_num failed: {}", ret);
            }
        }

        capability
    }
}

impl<T> From<T> for yh_capabilities
where
    T: AsRef<[Capability]> + IntoIterator<Item = Capability>,
{
    fn from(caps: T) -> Self {
        let joined_caps = caps.into_iter()
            .map(String::from)
            .collect::<Vec<String>>()
            .join(",");

        let cap_str = CString::new(joined_caps).unwrap();
        let mut capability = yh_capabilities {
            capabilities: [0; 8],
        };

        unsafe {
            let ret = ReturnCode::from(yh_capabilities_to_num(cap_str.as_ptr(), &mut capability));

            if ret != ReturnCode::Success {
                panic!("capabilities_to_num failed: {}", ret);
            }
        }

        capability
    }
}

#[derive(Clone, Debug)]
pub struct DeviceInfo {
    pub major_version: u8,
    pub minor_version: u8,
    pub patch_version: u8,
    pub serial: u32,
    pub log_capacity: u8,
    pub log_used: u8,
    pub algorithms: Vec<Algorithm>,
}

/// The public component of an asymmetric key stored on the device.
///
/// The contents of each variant correspond to the component(s) necessary to represent a public key
/// using that algorithm. For RSA, the contents are the public modulus `n`. For ECC, the first
/// component is the public point `x`, and the second component is the public point `y`. For EDC,
/// the contents are the public point `a` (compressed, per the Yubico documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Rsa(Vec<u8>),
    Ecc(Vec<u8>, Vec<u8>),
    Edc(Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Request(CommandType),
    Response(CommandType),
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandType {
    Echo,
    CreateSession,
    AuthSession,
    SessionMessage,
    GetDeviceInfo,
    Bsl,
    Reset,
    CloseSession,
    StorageStatistics,
    PutOpaque,
    GetOpaque,
    PutAuthKey,
    PutAsymmetricKey,
    GenerateAsymmetricKey,
    SignPkcs1,
    ListObjects,
    DecryptPkcs1,
    ExportWrapped,
    ImportWrapped,
    PutWrapKey,
    GetLogs,
    GetObjectInfo,
    PutOption,
    GetOption,
    GetPsuedoRandom,
    PutHmacKey,
    HmacData,
    GetPubkey,
    SignPss,
    SignEcdsa,
    DecryptEcdh,
    DeleteObject,
    DecryptOaep,
    GenerateHmacKey,
    GenerateWrapKey,
    VerifyHmac,
    SshCertify,
    PutTemplate,
    GetTemplate,
    OtpDecrypt,
    OtpAeadCreate,
    OtpAeadRandom,
    OtpAeadRewrap,
    AttestAsymmetric,
    PutOtpAeadKey,
    GenerateOtpAeadKey,
    SetLogIndex,
    WrapData,
    UnwrapData,
    SignEddsa,
    Blink,
    Error,
}

#[allow(non_upper_case_globals)]
impl From<u8> for Command {
    fn from(cmd: u8) -> Command {
        match cmd as u32 {
            yh_cmd_YHC_ECHO => Command::Request(CommandType::Echo),
            yh_cmd_YHC_CREATE_SES => Command::Request(CommandType::CreateSession),
            yh_cmd_YHC_AUTH_SES => Command::Request(CommandType::AuthSession),
            yh_cmd_YHC_SES_MSG => Command::Request(CommandType::SessionMessage),
            yh_cmd_YHC_GET_DEVICE_INFO => Command::Request(CommandType::GetDeviceInfo),
            yh_cmd_YHC_BSL => Command::Request(CommandType::Bsl),
            yh_cmd_YHC_RESET => Command::Request(CommandType::Reset),
            yh_cmd_YHC_CLOSE_SES => Command::Request(CommandType::CloseSession),
            yh_cmd_YHC_STATS => Command::Request(CommandType::StorageStatistics),
            yh_cmd_YHC_PUT_OPAQUE => Command::Request(CommandType::PutOpaque),
            yh_cmd_YHC_GET_OPAQUE => Command::Request(CommandType::GetOpaque),
            yh_cmd_YHC_PUT_AUTHKEY => Command::Request(CommandType::PutAuthKey),
            yh_cmd_YHC_PUT_ASYMMETRIC_KEY => Command::Request(CommandType::PutAsymmetricKey),
            yh_cmd_YHC_GEN_ASYMMETRIC_KEY => Command::Request(CommandType::GenerateAsymmetricKey),
            yh_cmd_YHC_SIGN_DATA_PKCS1 => Command::Request(CommandType::SignPkcs1),
            yh_cmd_YHC_LIST => Command::Request(CommandType::ListObjects),
            yh_cmd_YHC_DECRYPT_PKCS1 => Command::Request(CommandType::DecryptPkcs1),
            yh_cmd_YHC_EXPORT_WRAPPED => Command::Request(CommandType::ExportWrapped),
            yh_cmd_YHC_IMPORT_WRAPPED => Command::Request(CommandType::ImportWrapped),
            yh_cmd_YHC_PUT_WRAP_KEY => Command::Request(CommandType::PutWrapKey),
            yh_cmd_YHC_GET_LOGS => Command::Request(CommandType::GetLogs),
            yh_cmd_YHC_GET_OBJECT_INFO => Command::Request(CommandType::GetObjectInfo),
            yh_cmd_YHC_PUT_OPTION => Command::Request(CommandType::PutOption),
            yh_cmd_YHC_GET_OPTION => Command::Request(CommandType::GetOption),
            yh_cmd_YHC_GET_PSEUDO_RANDOM => Command::Request(CommandType::GetPsuedoRandom),
            yh_cmd_YHC_PUT_HMAC_KEY => Command::Request(CommandType::PutHmacKey),
            yh_cmd_YHC_HMAC_DATA => Command::Request(CommandType::HmacData),
            yh_cmd_YHC_GET_PUBKEY => Command::Request(CommandType::GetPubkey),
            yh_cmd_YHC_SIGN_DATA_PSS => Command::Request(CommandType::SignPss),
            yh_cmd_YHC_SIGN_DATA_ECDSA => Command::Request(CommandType::SignEcdsa),
            yh_cmd_YHC_DECRYPT_ECDH => Command::Request(CommandType::DecryptEcdh),
            yh_cmd_YHC_DELETE_OBJECT => Command::Request(CommandType::DeleteObject),
            yh_cmd_YHC_DECRYPT_OAEP => Command::Request(CommandType::DecryptOaep),
            yh_cmd_YHC_GENERATE_HMAC_KEY => Command::Request(CommandType::GenerateHmacKey),
            yh_cmd_YHC_GENERATE_WRAP_KEY => Command::Request(CommandType::GenerateWrapKey),
            yh_cmd_YHC_VERIFY_HMAC => Command::Request(CommandType::VerifyHmac),
            yh_cmd_YHC_SSH_CERTIFY => Command::Request(CommandType::SshCertify),
            yh_cmd_YHC_PUT_TEMPLATE => Command::Request(CommandType::PutTemplate),
            yh_cmd_YHC_GET_TEMPLATE => Command::Request(CommandType::GetTemplate),
            yh_cmd_YHC_OTP_DECRYPT => Command::Request(CommandType::OtpDecrypt),
            yh_cmd_YHC_OTP_AEAD_CREATE => Command::Request(CommandType::OtpAeadCreate),
            yh_cmd_YHC_OTP_AEAD_RANDOM => Command::Request(CommandType::OtpAeadRandom),
            yh_cmd_YHC_OTP_AEAD_REWRAP => Command::Request(CommandType::OtpAeadRewrap),
            yh_cmd_YHC_ATTEST_ASYMMETRIC => Command::Request(CommandType::AttestAsymmetric),
            yh_cmd_YHC_PUT_OTP_AEAD_KEY => Command::Request(CommandType::PutOtpAeadKey),
            yh_cmd_YHC_GENERATE_OTP_AEAD_KEY => Command::Request(CommandType::GenerateOtpAeadKey),
            yh_cmd_YHC_SET_LOG_INDEX => Command::Request(CommandType::SetLogIndex),
            yh_cmd_YHC_WRAP_DATA => Command::Request(CommandType::WrapData),
            yh_cmd_YHC_UNWRAP_DATA => Command::Request(CommandType::UnwrapData),
            yh_cmd_YHC_SIGN_DATA_EDDSA => Command::Request(CommandType::SignEddsa),
            yh_cmd_YHC_BLINK => Command::Request(CommandType::Blink),
            yh_cmd_YHC_ECHO_R => Command::Response(CommandType::Echo),
            yh_cmd_YHC_CREATE_SES_R => Command::Response(CommandType::CreateSession),
            yh_cmd_YHC_AUTH_SES_R => Command::Response(CommandType::AuthSession),
            yh_cmd_YHC_SES_MSG_R => Command::Response(CommandType::SessionMessage),
            yh_cmd_YHC_GET_DEVICE_INFO_R => Command::Response(CommandType::GetDeviceInfo),
            yh_cmd_YHC_BSL_R => Command::Response(CommandType::Bsl),
            yh_cmd_YHC_RESET_R => Command::Response(CommandType::Reset),
            yh_cmd_YHC_CLOSE_SES_R => Command::Response(CommandType::CloseSession),
            yh_cmd_YHC_STATS_R => Command::Response(CommandType::StorageStatistics),
            yh_cmd_YHC_PUT_OPAQUE_R => Command::Response(CommandType::PutOpaque),
            yh_cmd_YHC_GET_OPAQUE_R => Command::Response(CommandType::GetOpaque),
            yh_cmd_YHC_PUT_AUTHKEY_R => Command::Response(CommandType::PutAuthKey),
            yh_cmd_YHC_PUT_ASYMMETRIC_KEY_R => Command::Response(CommandType::PutAsymmetricKey),
            yh_cmd_YHC_GEN_ASYMMETRIC_KEY_R => {
                Command::Response(CommandType::GenerateAsymmetricKey)
            }
            yh_cmd_YHC_SIGN_DATA_PKCS1_R => Command::Response(CommandType::SignPkcs1),
            yh_cmd_YHC_LIST_R => Command::Response(CommandType::ListObjects),
            yh_cmd_YHC_DECRYPT_PKCS1_R => Command::Response(CommandType::DecryptPkcs1),
            yh_cmd_YHC_EXPORT_WRAPPED_R => Command::Response(CommandType::ExportWrapped),
            yh_cmd_YHC_IMPORT_WRAPPED_R => Command::Response(CommandType::ImportWrapped),
            yh_cmd_YHC_PUT_WRAP_KEY_R => Command::Response(CommandType::PutWrapKey),
            yh_cmd_YHC_GET_LOGS_R => Command::Response(CommandType::GetLogs),
            yh_cmd_YHC_GET_OBJECT_INFO_R => Command::Response(CommandType::GetObjectInfo),
            yh_cmd_YHC_PUT_OPTION_R => Command::Response(CommandType::PutOption),
            yh_cmd_YHC_GET_OPTION_R => Command::Response(CommandType::GetOption),
            yh_cmd_YHC_GET_PSEUDO_RANDOM_R => Command::Response(CommandType::GetPsuedoRandom),
            yh_cmd_YHC_PUT_HMAC_KEY_R => Command::Response(CommandType::PutHmacKey),
            yh_cmd_YHC_HMAC_DATA_R => Command::Response(CommandType::HmacData),
            yh_cmd_YHC_GET_PUBKEY_R => Command::Response(CommandType::GetPubkey),
            yh_cmd_YHC_SIGN_DATA_PSS_R => Command::Response(CommandType::SignPss),
            yh_cmd_YHC_SIGN_DATA_ECDSA_R => Command::Response(CommandType::SignEcdsa),
            yh_cmd_YHC_DECRYPT_ECDH_R => Command::Response(CommandType::DecryptEcdh),
            yh_cmd_YHC_DELETE_OBJECT_R => Command::Response(CommandType::DeleteObject),
            yh_cmd_YHC_DECRYPT_OAEP_R => Command::Response(CommandType::DecryptOaep),
            yh_cmd_YHC_GENERATE_HMAC_KEY_R => Command::Response(CommandType::GenerateHmacKey),
            yh_cmd_YHC_GENERATE_WRAP_KEY_R => Command::Response(CommandType::GenerateWrapKey),
            yh_cmd_YHC_VERIFY_HMAC_R => Command::Response(CommandType::VerifyHmac),
            yh_cmd_YHC_SSH_CERTIFY_R => Command::Response(CommandType::SshCertify),
            yh_cmd_YHC_PUT_TEMPLATE_R => Command::Response(CommandType::PutTemplate),
            yh_cmd_YHC_GET_TEMPLATE_R => Command::Response(CommandType::GetTemplate),
            yh_cmd_YHC_OTP_DECRYPT_R => Command::Response(CommandType::OtpDecrypt),
            yh_cmd_YHC_OTP_AEAD_CREATE_R => Command::Response(CommandType::OtpAeadCreate),
            yh_cmd_YHC_OTP_AEAD_RANDOM_R => Command::Response(CommandType::OtpAeadRandom),
            yh_cmd_YHC_OTP_AEAD_REWRAP_R => Command::Response(CommandType::OtpAeadRewrap),
            yh_cmd_YHC_ATTEST_ASYMMETRIC_R => Command::Response(CommandType::AttestAsymmetric),
            yh_cmd_YHC_PUT_OTP_AEAD_KEY_R => Command::Response(CommandType::PutOtpAeadKey),
            yh_cmd_YHC_GENERATE_OTP_AEAD_KEY_R => {
                Command::Response(CommandType::GenerateOtpAeadKey)
            }
            yh_cmd_YHC_SET_LOG_INDEX_R => Command::Response(CommandType::SetLogIndex),
            yh_cmd_YHC_WRAP_DATA_R => Command::Response(CommandType::WrapData),
            yh_cmd_YHC_UNWRAP_DATA_R => Command::Response(CommandType::UnwrapData),
            yh_cmd_YHC_SIGN_DATA_EDDSA_R => Command::Response(CommandType::SignEddsa),
            yh_cmd_YHC_BLINK_R => Command::Response(CommandType::Blink),
            yh_cmd_YHC_ERROR => Command::Response(CommandType::Error),
            _ => Command::Unknown,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Log {
    pub unlogged_boots: u16,
    pub unlogged_auths: u16,
    pub(crate) log_entries: Vec<LogEntry>,
}

impl Log {
    pub fn log_entries(&self) -> &[LogEntry] {
        &self.log_entries
    }
}

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub index: u16,
    pub command: Command,
    pub data_length: u16,
    pub session_key: u16,
    pub target_key: u16,
    pub second_key: u16,
    pub result: Command,
    pub systick: u32,
    digest: Vec<u8>,
}

impl LogEntry {
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

impl From<yh_log_entry> for LogEntry {
    fn from(entry: yh_log_entry) -> LogEntry {
        LogEntry {
            index: entry.number,
            command: Command::from(entry.command),
            data_length: entry.length,
            session_key: entry.session_key,
            target_key: entry.target_key,
            second_key: entry.second_key,
            result: Command::from(entry.result),
            systick: entry.systick,
            digest: Vec::from(entry.digest.as_ref()),
        }
    }
}

impl From<LogEntry> for yh_log_entry {
    fn from(entry: LogEntry) -> yh_log_entry {
        let mut digest_vec = entry.digest.clone();
        if digest_vec.len() < 16 {
            digest_vec.extend(&[0; 16]);
        }

        let digest_arr: [u8; 16] = [digest_vec.remove(0); 16];

        yh_log_entry {
            number: entry.index,
            command: 0,
            length: entry.data_length,
            session_key: entry.session_key,
            target_key: entry.target_key,
            second_key: entry.second_key,
            result: 0,
            systick: entry.systick,
            digest: digest_arr,
        }
    }
}
