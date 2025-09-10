use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Ident, Type};

#[proc_macro_derive(Obfuscate)]
pub fn derive_obfuscate(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let vis = &input.vis;
    let obf_name = Ident::new(&format!("Obfuscated{name}"), name.span());

    let data = match &input.data {
        Data::Struct(s) => s,
        _ => panic!("Obfuscate can only be derived for structs"),
    };

    let fields = match &data.fields {
        Fields::Named(fields) => &fields.named,
        _ => panic!("Only named fields are supported"),
    };

    let obf_fields = fields.iter().map(|f| {
        let name = &f.ident;
        quote! { #name: (Vec<u8>, [u8; 12]) }
    });

    let clear_args = fields.iter().map(|f| {
        let name = &f.ident;
        let ty = match &f.ty {
            Type::Path(p) if p.path.is_ident("String") => quote! { &str },
            Type::Path(p) if p.path.is_ident("u32") => quote! { u32 },
            Type::Path(p) if p.path.is_ident("u64") => quote! { u64 },
            Type::Path(p) if p.path.is_ident("i32") => quote! { i32 },
            Type::Path(p) if p.path.is_ident("i64") => quote! { i64 },
            Type::Path(p) if p.path.is_ident("bool") => quote! { bool },
            _ => quote! { &str },
        };
        quote! { #name: #ty }
    });

    let clear_encrypt = fields.iter().map(|f| {
        let name = &f.ident;
        match &f.ty {
            Type::Path(p) if p.path.is_ident("String") => quote! {
                #name: rustcrypt_core::encrypt_string(#name, &DEFAULT_KEY)
            },
            Type::Path(p) if p.path.is_ident("u32") => quote! {
                #name: rustcrypt_core::encrypt_u32(*#name, &DEFAULT_KEY)
            },
            Type::Path(p) if p.path.is_ident("u64") => quote! {
                #name: rustcrypt_core::encrypt_u64(*#name, &DEFAULT_KEY)
            },
            Type::Path(p) if p.path.is_ident("i32") => quote! {
                #name: rustcrypt_core::encrypt_i32(*#name, &DEFAULT_KEY)
            },
            Type::Path(p) if p.path.is_ident("i64") => quote! {
                #name: rustcrypt_core::encrypt_i64(*#name, &DEFAULT_KEY)
            },
            Type::Path(p) if p.path.is_ident("bool") => quote! {
                #name: rustcrypt_core::encrypt_bool(*#name, &DEFAULT_KEY)
            },
            _ => quote! {
                #name: rustcrypt_core::encrypt_string(#name, &DEFAULT_KEY)
            },
        }
    });

    let decrypt_fields = fields.iter().map(|f| {
        let name = &f.ident;
        match &f.ty {
            Type::Path(p) if p.path.is_ident("String") => quote! {
                #name: rustcrypt_core::decrypt_string(&self.#name.0, &self.#name.1, &DEFAULT_KEY)
            },
            Type::Path(p) if p.path.is_ident("u32") => quote! {
                #name: rustcrypt_core::decrypt_u32(&self.#name.0, &self.#name.1, &DEFAULT_KEY)
            },
            Type::Path(p) if p.path.is_ident("u64") => quote! {
                #name: rustcrypt_core::decrypt_u64(&self.#name.0, &self.#name.1, &DEFAULT_KEY)
            },
            Type::Path(p) if p.path.is_ident("i32") => quote! {
                #name: rustcrypt_core::decrypt_i32(&self.#name.0, &self.#name.1, &DEFAULT_KEY)
            },
            Type::Path(p) if p.path.is_ident("i64") => quote! {
                #name: rustcrypt_core::decrypt_i64(&self.#name.0, &self.#name.1, &DEFAULT_KEY)
            },
            Type::Path(p) if p.path.is_ident("bool") => quote! {
                #name: rustcrypt_core::decrypt_bool(&self.#name.0, &self.#name.1, &DEFAULT_KEY)
            },
            _ => quote! {
                #name: rustcrypt_core::decrypt_string(&self.#name.0, &self.#name.1, &DEFAULT_KEY)
            },
        }
    });

    let expanded = quote! {
        use rustcrypt_core::DEFAULT_KEY;

        #[derive(Clone)]
        #vis struct #obf_name { #(#obf_fields),* }

        impl #obf_name {
            pub fn new_clear(#(#clear_args),*) -> Self { Self { #(#clear_encrypt),* } }
            pub fn get_clear(&self) -> #name { #name { #(#decrypt_fields),* } }
        }
    };

    TokenStream::from(expanded)
}