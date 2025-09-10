use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr, LitByteStr, ExprArray, ItemFn};

#[proc_macro]
pub fn obfuscate_string(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let value = lit.value();
    
    let key = generate_compile_time_key(&value);
    let (encrypted_data, nonce) = encrypt_at_compile_time(&value, &key);
    
    let expanded = quote! {{
        const ENCRYPTED_DATA: &[u8] = &[#(#encrypted_data),*];
        const NONCE: &[u8; 12] = &[#(#nonce),*];
        const KEY: &[u8; 32] = &[#(#key),*];
        
        rustcrypt_core::decrypt_string(ENCRYPTED_DATA, NONCE, KEY)
    }};
    
    TokenStream::from(expanded)
}

#[proc_macro]
pub fn obfuscate_bytes(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitByteStr);
    let value = lit.value();
    
    let key = generate_compile_time_key_bytes(&value);
    let (encrypted_data, nonce) = encrypt_bytes_at_compile_time(&value, &key);
    
    let expanded = quote! {{
        const ENCRYPTED_DATA: &[u8] = &[#(#encrypted_data),*];
        const NONCE: &[u8; 12] = &[#(#nonce),*];
        const KEY: &[u8; 32] = &[#(#key),*];
        
        rustcrypt_core::decrypt_bytes(ENCRYPTED_DATA, NONCE, KEY)
    }};
    
    TokenStream::from(expanded)
}

#[proc_macro]
pub fn obfuscate_cstr(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let mut v = lit.value().into_bytes();
    v.push(0);
    let key = generate_compile_time_key_bytes(&v);
    let (encrypted_data, nonce) = encrypt_bytes_at_compile_time(&v, &key);
    let expanded = quote! {{
        const ENCRYPTED_DATA: &[u8] = &[#(#encrypted_data),*];
        const NONCE: &[u8; 12] = &[#(#nonce),*];
        const KEY: &[u8; 32] = &[#(#key),*];
        rustcrypt_core::decrypt_bytes(ENCRYPTED_DATA, NONCE, KEY)
    }};
    TokenStream::from(expanded)
}

#[proc_macro]
pub fn obfuscate_bytes_array(input: TokenStream) -> TokenStream {
    let arr = parse_macro_input!(input as ExprArray);
    let mut values: Vec<u8> = Vec::new();
    for elem in arr.elems.iter() {
        if let syn::Expr::Lit(l) = elem {
            if let syn::Lit::Int(i) = &l.lit {
                if let Ok(v) = i.base10_parse::<u64>() { values.push((v & 0xFF) as u8); }
            }
        }
    }
    let key = generate_compile_time_key_bytes(&values);
    let (encrypted_data, nonce) = encrypt_bytes_at_compile_time(&values, &key);
    let expanded = quote! {{
        const ENCRYPTED_DATA: &[u8] = &[#(#encrypted_data),*];
        const NONCE: &[u8; 12] = &[#(#nonce),*];
        const KEY: &[u8; 32] = &[#(#key),*];
        rustcrypt_core::decrypt_bytes(ENCRYPTED_DATA, NONCE, KEY)
    }};
    TokenStream::from(expanded)
}

#[proc_macro]
pub fn obfuscate_flow(input: TokenStream) -> TokenStream {
    let _input = input;
    let expanded = quote! {{
        let mut _dummy = 0u64;
        for i in 0..16 {
            _dummy = _dummy.wrapping_add(i);
            _dummy = _dummy.rotate_left(3);
            _dummy ^= 0x5A5A5A5A5A5A5A5A;
        }
        std::hint::black_box(_dummy);
    }};
    
    TokenStream::from(expanded)
}

#[proc_macro]
pub fn obfuscate_flow_heavy(input: TokenStream) -> TokenStream {
    let _input = input;
    let expanded = quote! {{
        let mut _d0: u64 = 0xA5A5A5A5A5A5A5A5;
        let mut _d1: u64 = 0x5A5A5A5A5A5A5A5A;
        for i in 0..128u64 {
            _d0 = _d0.rotate_left((i % 63) as u32) ^ i;
            _d1 = _d1.wrapping_add(_d0 ^ (i.wrapping_mul(0x9E3779B97F4A7C15)));
            if (_d0 & 1) == 0 { _d1 ^= _d0.rotate_right(7); } else { _d0 ^= _d1.rotate_left(11); }
        }
        std::hint::black_box((_d0, _d1));
    }};
    TokenStream::from(expanded)
}

#[proc_macro]
pub fn obfuscate_branch(input: TokenStream) -> TokenStream {
    let cond = parse_macro_input!(input as syn::Expr);
    let expanded = quote! {{
        let __c = { #cond };
        let mut __t: u64 = 0x9E3779B97F4A7C15;
        for i in 0..32u64 { __t ^= __t.rotate_left((i % 17) as u32) ^ i; }
        let __opaque = ((__t ^ 0xA5A5A5A5A5A5A5A5) & 1) == 0;
        __c && (__opaque || !__opaque)
    }};
    TokenStream::from(expanded)
}

// attribute macro to inject obfuscation into functions
#[proc_macro_attribute]
pub fn obfuscate_fn(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut f = parse_macro_input!(item as ItemFn);
    let prologue = quote! {{
        let mut __a: u64 = 0xC3D2E1F0A5968778;
        for i in 0..64u64 { __a = __a.rotate_left((i%23) as u32) ^ (i.wrapping_mul(0x9E37)); }
        std::hint::black_box(__a);
    }};
    let epilogue = quote! {{
        let mut __b: u64 = 0x0123456789ABCDEF;
        for i in 0..64u64 { __b = __b.rotate_right((i%19) as u32) ^ (i.wrapping_mul(0xA5A5)); }
        std::hint::black_box(__b);
    }};
    let orig_block = *f.block;
    let new_block = quote! {{
        #prologue
        let __ret = (|| #orig_block)();
        #epilogue
        __ret
    }};
    f.block = syn::parse2(new_block).expect("valid block");
    TokenStream::from(quote! { #f })
}

#[proc_macro]
pub fn obfuscate_select(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::ExprTuple);
    let mut it = input.elems.into_iter();
    let cond = it.next().expect("cond");
    let t = it.next().expect("true");
    let f = it.next().expect("false");
    let expanded = quote! {{
        let __c = { #cond };
        let mut __z: u64 = 0x6A09E667F3BCC909;
        for i in 0..16u64 { __z ^= __z.rotate_left((i%13) as u32) ^ (i*0x9E37); }
        let __op = ((__z ^ 0xBB67AE8584CAA73B) & 1) == 1;
        if __c && (__op || !__op) { (#t)() } else { (#f)() }
    }};
    TokenStream::from(expanded)
}

#[proc_macro]
pub fn obfuscate_loop(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::ExprTuple);
    let mut it = input.elems.into_iter();
    let n = it.next().expect("count");
    let body = it.next().expect("body");
    let expanded = quote! {{
        let __n: usize = (#n) as usize;
        let mut __acc: u64 = 0;
        for i in 0..__n { __acc ^= ((i as u64).wrapping_mul(0x9E3779B97F4A7C15)).rotate_left((i%23) as u32); (#body); }
        std::hint::black_box(__acc);
    }};
    TokenStream::from(expanded)
}

#[proc_macro]
pub fn obfuscate_const_bytes(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitByteStr);
    let value = lit.value();
    let key = generate_compile_time_key_bytes(&value);
    let (encrypted_data, nonce) = encrypt_bytes_at_compile_time(&value, &key);
    let expanded = quote! {{
        const ENCRYPTED_DATA: &[u8] = &[#(#encrypted_data),*];
        const NONCE: &[u8; 12] = &[#(#nonce),*];
        const KEY: &[u8; 32] = &[#(#key),*];
        rustcrypt_core::decrypt_bytes(ENCRYPTED_DATA, NONCE, KEY)
    }};
    TokenStream::from(expanded)
}

#[proc_macro]
pub fn obfuscate_call(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::ExprCall);
    
    let func = &input.func;
    
    let expanded = quote! {{
        let mut _func_ptr: fn() -> _ = unsafe { std::mem::transmute(#func) };
        let _obfuscated = _func_ptr as usize;
        let _deobfuscated = _obfuscated ^ 0xDEADBEEF;
        let _final_func: fn() -> _ = unsafe { std::mem::transmute(_deobfuscated) };
        _final_func()
    }};
    
    TokenStream::from(expanded)
}

fn generate_compile_time_key(input: &str) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    let hash = hasher.finish();
    
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = ((hash >> (i % 8)) & 0xFF) as u8;
    }
    key
}

fn generate_compile_time_key_bytes(input: &[u8]) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    let hash = hasher.finish();
    
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = ((hash >> (i % 8)) & 0xFF) as u8;
    }
    key
}

fn encrypt_at_compile_time(input: &str, key: &[u8; 32]) -> (Vec<u8>, [u8; 12]) {
    let bytes = input.as_bytes();
    let mut encrypted = Vec::new();
    
    for (i, &byte) in bytes.iter().enumerate() {
        encrypted.push(byte ^ key[i % 32]);
    }
    let mut nonce = [0u8; 12];
    for i in 0..12 {
        nonce[i] = key[i % 32];
    }
    
    (encrypted, nonce)
}

fn encrypt_bytes_at_compile_time(input: &[u8], key: &[u8; 32]) -> (Vec<u8>, [u8; 12]) {
    let mut encrypted = Vec::new();
    
    for (i, &byte) in input.iter().enumerate() {
        encrypted.push(byte ^ key[i % 32]);
    }
    let mut nonce = [0u8; 12];
    for i in 0..12 {
        nonce[i] = key[i % 32];
    }
    
    (encrypted, nonce)
}