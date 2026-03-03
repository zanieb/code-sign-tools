use zeroize::Zeroize;

/// A wrapper that redacts its contents in `Debug` output and zeroizes on drop.
///
/// Use for sensitive values (passwords, certificates) to prevent accidental logging
/// and ensure memory is cleared when no longer needed.
///
/// Access the inner value explicitly via [`expose`](Secret::expose).
#[derive(Clone)]
pub(crate) struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    pub(crate) fn new(val: T) -> Self {
        Self(val)
    }

    /// Explicitly access the secret value.
    pub(crate) fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}
