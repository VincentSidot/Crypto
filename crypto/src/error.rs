macro_rules! error {
    ($kind:ident, $($arg:expr),+) => {
        std::io::Error::new(std::io::ErrorKind::$kind, error!(@msg $($arg),+))
    };
    (@msg $pattern:literal) => {
        $pattern
    };
    (@msg $pattern:literal, $($arg:expr),+) => {
        format!($pattern, $($arg),+)
    };
}
pub(crate) use error;

pub type Result<T> = std::result::Result<T, std::io::Error>;
