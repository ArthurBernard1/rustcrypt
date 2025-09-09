use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitByteStr, LitStr};

#[proc_macro]
pub fn obf_lit(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let bytes = lit.value().into_bytes();

    let mut keystream = Vec::with_capacity(bytes.len());
    let mut s: u64 = 0xA076_1D64 ^ (bytes.len() as u64).wrapping_mul(0x9E37_79B9);
    for _ in 0..bytes.len() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        keystream.push(((s ^ (s >> 11)) & 0xFF) as u8);
    }

    let obf: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ keystream[i])
        .collect();

    let n = obf.len();
    let obf_tokens = quote! { [#(#obf),*] };
    let key_tokens = quote! { [#(#keystream),*] };

    let expanded = quote! {{
        const __OBF: [u8; #n] = #obf_tokens;
        const __KEY: [u8; #n] = #key_tokens;
        let mut __buf = vec![0u8; #n];
        let mut __i = 0usize;
        while __i < #n { __buf[__i] = __OBF[__i] ^ __KEY[__i]; __i += 1; }
        String::from_utf8(__buf).expect("obf_lit produced invalid UTF-8")
    }};

    TokenStream::from(expanded)
}

/// Obfuscate a byte string literal at compile time and produce a runtime `Vec<u8>`.
#[proc_macro]
pub fn obf_lit_bytes(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitByteStr);
    let bytes = lit.value();

    let mut keystream = Vec::with_capacity(bytes.len());
    let mut s: u64 = 0xA076_1D64 ^ (bytes.len() as u64).wrapping_mul(0x9E37_79B9);
    for _ in 0..bytes.len() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        keystream.push(((s ^ (s >> 11)) & 0xFF) as u8);
    }

    let obf: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ keystream[i])
        .collect();

    let n = obf.len();
    let obf_tokens = quote! { [#(#obf),*] };
    let key_tokens = quote! { [#(#keystream),*] };

    let expanded = quote! {{
        const __OBF: [u8; #n] = #obf_tokens;
        const __KEY: [u8; #n] = #key_tokens;
        let mut __buf = vec![0u8; #n];
        let mut __i = 0usize;
        while __i < #n { __buf[__i] = __OBF[__i] ^ __KEY[__i]; __i += 1; }
        __buf
    }};

    TokenStream::from(expanded)
}

#[proc_macro]
pub fn obf_lit_cstr(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let mut bytes = lit.value().into_bytes();
    bytes.push(0);
    let mut keystream = Vec::with_capacity(bytes.len());
    let mut s: u64 = 0xA076_1D64 ^ (bytes.len() as u64).wrapping_mul(0x9E37_79B9);
    for _ in 0..bytes.len() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; keystream.push(((s ^ (s >> 11)) & 0xFF) as u8); }
    let obf: Vec<u8> = bytes.iter().enumerate().map(|(i, b)| b ^ keystream[i]).collect();
    let n = obf.len();
    let obf_tokens = quote! { [#(#obf),*] };
    let key_tokens = quote! { [#(#keystream),*] };
    let expanded = quote! {{
        const __OBF: [u8; #n] = #obf_tokens;
        const __KEY: [u8; #n] = #key_tokens;
        let mut __buf = vec![0u8; #n];
        let mut __i = 0usize;
        while __i < #n { __buf[__i] = __OBF[__i] ^ __KEY[__i]; __i += 1; }
        __buf
    }};
    TokenStream::from(expanded)
}

#[proc_macro]
pub fn obf_lit_array(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitByteStr);
    let bytes = lit.value();
    let mut keystream = Vec::with_capacity(bytes.len());
    let mut s: u64 = 0xA076_1D64 ^ (bytes.len() as u64).wrapping_mul(0x9E37_79B9);
    for _ in 0..bytes.len() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; keystream.push(((s ^ (s >> 11)) & 0xFF) as u8); }
    let obf: Vec<u8> = bytes.iter().enumerate().map(|(i, b)| b ^ keystream[i]).collect();
    let n = obf.len();
    let obf_tokens = quote! { [#(#obf),*] };
    let key_tokens = quote! { [#(#keystream),*] };
    let expanded = quote! {{
        const __OBF: [u8; #n] = #obf_tokens;
        const __KEY: [u8; #n] = #key_tokens;
        (__OBF, __KEY)
    }};
    TokenStream::from(expanded)
}