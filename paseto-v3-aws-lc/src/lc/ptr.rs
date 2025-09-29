// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use core::ops::Deref;
use std::marker::PhantomData;

use paseto_core::PasetoError;

use crate::lc::aws_lc::{
    BIGNUM, BN_free, EC_GROUP, EC_GROUP_free, EC_KEY, EC_KEY_free, EC_POINT, EC_POINT_free,
    ECDSA_SIG, ECDSA_SIG_free, OPENSSL_free,
};

pub(crate) type LcPtr<T> = ManagedPointer<*mut T>;
pub(crate) type DetachableLcPtr<T> = DetachablePointer<*mut T>;

#[derive(Debug)]
pub(crate) struct ManagedPointer<P: Pointer> {
    pointer: P,
}

impl<P: Pointer> ManagedPointer<P> {
    #[inline]
    pub fn new<T: IntoPointer<P>>(value: T) -> Result<Self, PasetoError> {
        if let Some(pointer) = value.into_pointer() {
            Ok(Self { pointer })
        } else {
            Err(PasetoError::CryptoError)
        }
    }
}

impl<P: Pointer> Drop for ManagedPointer<P> {
    #[inline]
    fn drop(&mut self) {
        self.pointer.free();
    }
}

impl<'a, P: Pointer> From<&'a ManagedPointer<P>> for ConstPointer<'a, P::T> {
    fn from(ptr: &'a ManagedPointer<P>) -> ConstPointer<'a, P::T> {
        ConstPointer {
            ptr: ptr.pointer.as_const_ptr(),
            _lifetime: PhantomData,
        }
    }
}

impl<P: Pointer> ManagedPointer<P> {
    #[inline]
    pub fn as_const(&self) -> ConstPointer<'_, P::T> {
        self.into()
    }

    #[inline]
    pub fn as_mut(&mut self) -> MutPointer<P::T> {
        MutPointer {
            ptr: self.pointer.as_mut_ptr(),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub(crate) struct DetachablePointer<P: Pointer> {
    pointer: Option<P>,
}

impl<P: Pointer> Deref for DetachablePointer<P> {
    type Target = P;
    #[inline]
    fn deref(&self) -> &Self::Target {
        match &self.pointer {
            Some(pointer) => pointer,
            None => {
                // Safety: pointer is only None when DetachableLcPtr is detached or dropped
                unreachable!()
            }
        }
    }
}

impl<P: Pointer> DetachablePointer<P> {
    #[inline]
    pub fn new<T: IntoPointer<P>>(value: T) -> Result<Self, PasetoError> {
        if let Some(pointer) = value.into_pointer() {
            Ok(Self {
                pointer: Some(pointer),
            })
        } else {
            Err(PasetoError::CryptoError)
        }
    }

    #[inline]
    pub fn detach(mut self) -> P {
        self.pointer.take().unwrap()
    }
}

impl<P: Pointer> From<DetachablePointer<P>> for ManagedPointer<P> {
    #[inline]
    fn from(mut dptr: DetachablePointer<P>) -> Self {
        match dptr.pointer.take() {
            Some(pointer) => ManagedPointer { pointer },
            None => {
                // Safety: pointer is only None when DetachableLcPtr is detached or dropped
                unreachable!()
            }
        }
    }
}

impl<P: Pointer> Drop for DetachablePointer<P> {
    #[inline]
    fn drop(&mut self) {
        if let Some(mut pointer) = self.pointer.take() {
            pointer.free();
        }
    }
}

#[derive(Debug)]
pub(crate) struct ConstPointer<'a, T> {
    ptr: *const T,
    _lifetime: PhantomData<&'a T>,
}

impl<T> Copy for ConstPointer<'_, T> {}
impl<T> Clone for ConstPointer<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> ConstPointer<'static, T> {
    pub unsafe fn new_static(ptr: *const T) -> Result<Self, PasetoError> {
        if ptr.is_null() {
            return Err(PasetoError::CryptoError);
        }
        Ok(ConstPointer {
            ptr,
            _lifetime: PhantomData,
        })
    }
}

impl<T> ConstPointer<'_, T> {
    pub fn project<'a, C>(
        &'a self,
        f: unsafe fn(&'a Self) -> *const C,
    ) -> Result<ConstPointer<'a, C>, PasetoError> {
        let ptr = unsafe { f(self) };
        if ptr.is_null() {
            return Err(PasetoError::CryptoError);
        }
        Ok(ConstPointer {
            ptr,
            _lifetime: PhantomData,
        })
    }
}

impl<T> Deref for ConstPointer<'_, T> {
    type Target = *const T;

    fn deref(&self) -> &Self::Target {
        &self.ptr
    }
}

#[derive(Debug)]
pub(crate) struct MutPointer<T> {
    ptr: *mut T,
}

impl<T> Deref for MutPointer<T> {
    type Target = *mut T;

    fn deref(&self) -> &Self::Target {
        &self.ptr
    }
}

pub(crate) trait Pointer {
    type T;

    fn free(&mut self);
    fn as_const_ptr(&self) -> *const Self::T;
    fn as_mut_ptr(&mut self) -> *mut Self::T;
}

pub(crate) trait IntoPointer<P> {
    fn into_pointer(self) -> Option<P>;
}

impl<T> IntoPointer<*mut T> for *mut T {
    #[inline]
    fn into_pointer(self) -> Option<*mut T> {
        if self.is_null() { None } else { Some(self) }
    }
}

macro_rules! create_pointer {
    ($ty:ty, $free:path) => {
        impl Pointer for *mut $ty {
            type T = $ty;

            #[inline]
            fn free(&mut self) {
                unsafe {
                    let ptr = *self;
                    $free(ptr.cast());
                }
            }

            #[inline]
            fn as_const_ptr(&self) -> *const Self::T {
                self.cast()
            }

            #[inline]
            fn as_mut_ptr(&mut self) -> *mut Self::T {
                *self
            }
        }
    };
}

// `OPENSSL_free` and the other `XXX_free` functions perform a zeroization of the memory when it's
// freed. This is different than functions of the same name in OpenSSL which generally do not zero
// memory.
create_pointer!(u8, OPENSSL_free);
create_pointer!(EC_GROUP, EC_GROUP_free);
create_pointer!(EC_POINT, EC_POINT_free);
create_pointer!(EC_KEY, EC_KEY_free);
create_pointer!(ECDSA_SIG, ECDSA_SIG_free);
create_pointer!(BIGNUM, BN_free);
