#[proc_macro_derive(FromNum)]
pub fn derive_from_num(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    derive_from_num_impl(syn::parse_macro_input!(input as syn::DeriveInput)).into()
}

fn compile_error(span: &impl syn::spanned::Spanned, message: &str) -> proc_macro2::TokenStream {
    syn::Error::new(span.span(), message).to_compile_error()
}

fn derive_from_num_impl(input: syn::DeriveInput) -> proc_macro2::TokenStream {
    let ident = input.ident.clone();

    let data = if let syn::Data::Enum(data) = input.data.clone() {
        data
    } else {
        return compile_error(&input, "FromNum can only be derived for enums");
    };

    let repr = match input.attrs.iter().find(|attr| {
        if let Some(ident) = attr.path.get_ident() {
            ident == "repr"
        } else {
            false
        }
    }) {
        Some(attr) => attr.parse_args::<syn::Path>().unwrap(),
        None => {
            return compile_error(&input, "Cannot derive an enum that is not `repr(_num_)`");
        }
    };

    let variants = data
        .variants
        .iter()
        .map(|v| v.ident.clone())
        .collect::<Vec<_>>();

    quote::quote! {
        impl #ident {
            fn from_num(num: #repr) -> Option<Self> {
                #(if Self::#variants as #repr == num { return Some(Self::#variants); })*
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success() {
        let input = quote::quote! {
            #[repr(u8)]
            enum S {
                One = 1,
                Two = 2,
            }
        };

        let expected = quote::quote! {
            impl S {
                fn from_num(num: u8) -> Option<Self> {
                    if Self::One as u8 == num { return Some(Self::One); }
                    if Self::Two as u8 == num { return Some(Self::Two); }
                    None
                }
            }
        };

        assert_eq!(
            derive_from_num_impl(syn::parse2(input).unwrap()).to_string(),
            expected.to_string()
        );
    }

    #[test]
    fn non_enum() {
        let input = quote::quote! {
            struct S {
                string: String,
            }
        };

        assert_eq!(
            derive_from_num_impl(syn::parse2::<syn::DeriveInput>(input).unwrap()).to_string(),
            "compile_error ! { \"FromNum can only be derived for enums\" }"
        );
    }

    #[test]
    fn non_num_enum() {
        let input = quote::quote! {
            enum S {
               String,
            }
        };

        assert_eq!(
            derive_from_num_impl(syn::parse2::<syn::DeriveInput>(input).unwrap()).to_string(),
            "compile_error ! { \"Cannot derive an enum that is not `repr(_num_)`\" }"
        );
    }
}
