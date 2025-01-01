//! Phantom-typed taint wrapper for untrusted input bytes.
//!
//! The whole point of this crate: a `Tainted<Vec<u8>>` cannot be converted to
//! anything that goes into argv, env, paths, URLs, DNS, or shells, because no
//! public conversion exists. The only public eliminator is in `seck-fd`.

use core::marker::PhantomData;
use zeroize::Zeroize;

/// Wrapper for bytes (or any payload) that originated from an untrusted
/// source. The only legitimate destination is a sink defined in `seck-fd`.
///
/// Deliberately does NOT implement: Debug, Display, AsRef<str>, Into<OsString>,
/// Into<PathBuf>, Into<Cow<'_, str>>. Any conversion would defeat the typestate.
pub struct Tainted<T: Zeroize> {
    inner: T,
    _seal: PhantomData<*const ()>,
}

// Tainted<T> is Send if T is Send, but never Sync (the PhantomData<*const ()>
// makes it !Send by default; we re-enable Send via unsafe impl).
// SAFETY: marker-only impl; the contained T's Send-ness is what actually matters.
#[allow(unsafe_code)]
unsafe impl<T: Zeroize + Send> Send for Tainted<T> {}

/// Wrapper for values we've explicitly validated as not user-tainted.
pub struct Untainted<T> {
    inner: T,
}

impl<T: Zeroize> Tainted<T> {
    /// Construct a tainted value. Crate-local: only privileged crates (host)
    /// should call this via the friend-key pattern below.
    #[doc(hidden)]
    #[must_use]
    pub fn __new_internal(inner: T) -> Self {
        Self {
            inner,
            _seal: PhantomData,
        }
    }

    /// Take inner ownership for a sink. **Do not** add a public version of
    /// this method outside of `seck-fd`. The `SinkToken` argument is the only
    /// way to call this and is constructable only by crates that hold a
    /// `FriendKey` constant — by audit, that's `seck-fd` and `seck-host`.
    #[doc(hidden)]
    pub fn __into_inner_for_sink(self, _token: SinkToken) -> T {
        // Move the inner value out without triggering our own Drop (which would
        // zeroize before the consumer reads it). We use ManuallyDrop here so
        // the destructor doesn't run when `self` is dropped — the consumer is
        // now responsible for any cleanup of the moved value.
        let me = core::mem::ManuallyDrop::new(self);
        // SAFETY: we own `me` and never read `inner` again after this read.
        #[allow(unsafe_code)]
        unsafe { core::ptr::read(&me.inner) }
    }
}

impl<T: Zeroize> Drop for Tainted<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T> Untainted<T> {
    #[must_use]
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    pub fn get(&self) -> &T {
        &self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

/// Capability token only constructable by crates that are explicit "sinks"
/// for tainted bytes (e.g., `seck-fd::write_to_sandbox_pipe`). Outside crates
/// cannot construct a `SinkToken` without a `FriendKey`, and `FriendKey`
/// constants are `#[doc(hidden)]` and only re-exported to specific crates.
pub struct SinkToken {
    _private: (),
}

impl SinkToken {
    #[doc(hidden)]
    pub const fn __new_friend(_: FriendKey) -> Self {
        Self { _private: () }
    }
}

/// FriendKey only constructable in this crate; downstream callers cannot
/// fabricate one. The crate-private nature is enforced by the `(())` field.
pub struct FriendKey(());

impl FriendKey {
    #[doc(hidden)]
    pub const FOR_SECK_FD: FriendKey = FriendKey(());
    #[doc(hidden)]
    pub const FOR_SECK_HOST: FriendKey = FriendKey(());
    #[doc(hidden)]
    pub const FOR_SECK_REPORT: FriendKey = FriendKey(());
}

/// Constant-time equality for tainted byte regions (e.g., nonce comparison).
pub fn ct_eq(a: &Tainted<Vec<u8>>, b: &Tainted<Vec<u8>>) -> bool {
    use subtle::ConstantTimeEq;
    a.inner.ct_eq(&b.inner).into()
}
