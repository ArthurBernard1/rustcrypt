#[macro_export]
macro_rules! obf_lit {
    ($s:literal) => {
        $crate::rustcrypt_ct_macros::obf_lit!($s)
    };
}

#[macro_export]
macro_rules! obf_lit_bytes {
    ($b:literal) => {
        $crate::rustcrypt_ct_macros::obf_lit_bytes!($b)
    };
}

#[macro_export]
macro_rules! obf_lit_cstr {
    ($s:literal) => {{
        $crate::rustcrypt_ct_macros::obf_lit_cstr!($s)
    }}
}

#[macro_export]
macro_rules! obf_lit_array {
    ($b:literal) => {{
        $crate::rustcrypt_ct_macros::obf_lit_array!($b)
    }}
}

 

#[macro_export]
macro_rules! obf_format {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        format!("{}", $crate::obf_lit!($fmt), $( $arg ),* )
    }}
}

#[macro_export]
macro_rules! obf_secret_str {
    ($lit:literal) => {{
        let s = $crate::obf_lit!($lit);
        $crate::SecretVecAlias::new(s.into_bytes())
    }}
}

#[macro_export]
macro_rules! obf_hide {
    ($rc:expr, $lit:literal) => {{
        $rc.hide(&$crate::obf_lit!($lit))
    }}
}

#[macro_export]
macro_rules! obf_hide_bytes {
    ($rc:expr, $blit:literal) => {{
        $rc.hide_bytes(&$crate::obf_lit_bytes!($blit))
    }}
}