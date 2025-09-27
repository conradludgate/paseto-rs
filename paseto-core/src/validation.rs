use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;

use crate::PasetoError;

pub trait Validate {
    /// The type of claim that can be validated
    type Claims;

    /// The validation to perform on the claims
    fn validate(&self, claims: &Self::Claims) -> Result<(), PasetoError>;

    /// Extend the validation with another validation.
    fn then<V>(self, other: V) -> impl Validate<Claims = Self::Claims>
    where
        Self: Sized,
        V: Validate<Claims = Self::Claims>,
    {
        ValidateThen(self, other)
    }

    fn map<T>(self, f: impl for<'a> Fn(&'a T) -> &'a Self::Claims) -> impl Validate<Claims = T>
    where
        Self: Sized,
    {
        Map(PhantomData::<T>, f, self)
    }
}

pub struct NoValidation<Claims>(PhantomData<Claims>);

impl<Claims> NoValidation<Claims> {
    pub fn dangerous_no_validation() -> Self {
        NoValidation(PhantomData)
    }
}

impl<Claims> Validate for NoValidation<Claims> {
    type Claims = Claims;
    fn validate(&self, _: &Self::Claims) -> Result<(), PasetoError> {
        Ok(())
    }
}

struct Map<Claims, F, T>(PhantomData<Claims>, F, T);

impl<Claims, F, T> Validate for Map<Claims, F, T>
where
    F: for<'a> Fn(&'a Claims) -> &'a T::Claims,
    T: Validate,
{
    type Claims = Claims;

    fn validate(&self, claims: &Self::Claims) -> Result<(), PasetoError> {
        self.2.validate((self.1)(claims))
    }
}
struct ValidateThen<T, U>(T, U);

impl<T: Validate, U: Validate<Claims = T::Claims>> Validate for ValidateThen<T, U> {
    type Claims = T::Claims;

    fn validate(&self, claims: &Self::Claims) -> Result<(), PasetoError> {
        self.0.validate(claims)?;
        self.1.validate(claims)
    }
}

impl<T: Validate> Validate for Vec<T> {
    type Claims = T::Claims;

    fn validate(&self, claims: &Self::Claims) -> Result<(), PasetoError> {
        <[T]>::validate(self, claims)
    }
}

impl<T: Validate> Validate for [T] {
    type Claims = T::Claims;

    fn validate(&self, claims: &Self::Claims) -> Result<(), PasetoError> {
        for v in self {
            T::validate(v, claims)?;
        }
        Ok(())
    }
}

impl<T: Validate + ?Sized> Validate for Box<T> {
    type Claims = T::Claims;

    fn validate(&self, claims: &Self::Claims) -> Result<(), PasetoError> {
        T::validate(self, claims)
    }
}

impl<T: Validate + ?Sized> Validate for Arc<T> {
    type Claims = T::Claims;

    fn validate(&self, claims: &Self::Claims) -> Result<(), PasetoError> {
        T::validate(self, claims)
    }
}

impl<T: Validate + ?Sized> Validate for Rc<T> {
    type Claims = T::Claims;

    fn validate(&self, claims: &Self::Claims) -> Result<(), PasetoError> {
        T::validate(self, claims)
    }
}
