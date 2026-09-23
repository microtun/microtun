use heck::{ToKebabCase, ToShoutySnakeCase};
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Attribute, Data, DataEnum, DataStruct, DeriveInput, Expr, Fields, GenericArgument, Generics,
    Lit, LitChar, LitStr, Path, PathArguments, Type, parse_macro_input, parse_quote,
};

#[proc_macro_derive(Parser, attributes(command, arg, value, dispatch))]
pub fn derive_parser(input: TokenStream) -> TokenStream {
    expand_parser(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_derive(Subcommand, attributes(command, arg, value, dispatch))]
pub fn derive_subcommand(input: TokenStream) -> TokenStream {
    expand_subcommand(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_derive(Args, attributes(command, arg, value))]
pub fn derive_args(input: TokenStream) -> TokenStream {
    expand_args(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_derive(ValueEnum, attributes(value))]
pub fn derive_value_enum(input: TokenStream) -> TokenStream {
    expand_value_enum(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_derive(Dispatch, attributes(command, dispatch, arg))]
pub fn derive_dispatch(input: TokenStream) -> TokenStream {
    expand_dispatch(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[derive(Default)]
struct ContainerAttrs {
    name: Option<String>,
    about: Option<String>,
    version: Option<String>,
}

#[derive(Default, Clone)]
struct CommandAttrs {
    name: Option<String>,
    about: Option<String>,
    aliases: Vec<String>,
    visible_aliases: Vec<String>,
    handler: Option<Path>,
    flatten: bool,
}

#[derive(Default, Clone)]
struct FieldAttrs {
    short_set: bool,
    short: Option<char>,
    long_set: bool,
    long: Option<String>,
    global: bool,
    default: Option<Expr>,
    value_enum: bool,
    value_name: Option<String>,
    help: Option<String>,
    subcommand: bool,
    flatten: bool,
    action_count: bool,
    action_set_false: bool,
    aliases: Vec<String>,
    visible_aliases: Vec<String>,
    required: Option<bool>,
    allow_hyphen_values: bool,
}

const UNKNOWN_ARG_KEY: &str = "unrecognized `arg` key; expected one of `short`, `long`, `global`, \
     `default_value_t`, `value_enum`, `value_name`, `help`, `alias`, `visible_alias`, `required`, \
     `allow_hyphen_values`, `action`";

const UNKNOWN_COMMAND_KEY: &str = "unrecognized `command` key; expected one of `name`, `about`, \
     `version`, `alias`, `visible_alias`, `handler`, `crate`";

/// Reject two arguments (or two commands) that would answer to the same name.
///
/// Auto-derived shorts come from the first letter of the field name, so collisions are easy to
/// introduce by accident and otherwise resolve silently in field-declaration order.
#[derive(Default)]
struct NameSet {
    seen: std::collections::HashSet<String>,
}

impl NameSet {
    fn insert<T: quote::ToTokens>(&mut self, name: String, spanned: &T) -> syn::Result<()> {
        if !self.seen.insert(name.clone()) {
            return Err(syn::Error::new_spanned(
                spanned,
                format!("duplicate name `{name}`; each name may only be declared once"),
            ));
        }
        Ok(())
    }
}

fn doc_string(attrs: &[Attribute]) -> String {
    let mut lines = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("doc") {
            continue;
        }
        if let syn::Meta::NameValue(meta) = &attr.meta {
            if let Expr::Lit(expr) = &meta.value {
                if let Lit::Str(value) = &expr.lit {
                    let text = value.value();
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        lines.push(trimmed.to_owned());
                    }
                }
            }
        }
    }
    lines.join(" ")
}

fn parse_container_attrs(attrs: &[Attribute]) -> syn::Result<ContainerAttrs> {
    let mut out = ContainerAttrs::default();
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("command")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("name") {
                out.name = Some(meta.value()?.parse::<LitStr>()?.value());
            } else if meta.path.is_ident("about") {
                out.about = Some(meta.value()?.parse::<LitStr>()?.value());
            } else if meta.path.is_ident("version") {
                out.version = Some(meta.value()?.parse::<LitStr>()?.value());
            } else if meta.path.is_ident("crate") {
                let _ = meta.value()?.parse::<Path>()?;
            } else {
                return Err(meta.error(UNKNOWN_COMMAND_KEY));
            }
            Ok(())
        })?;
    }
    Ok(out)
}

fn parse_command_attrs(attrs: &[Attribute]) -> syn::Result<CommandAttrs> {
    let mut out = CommandAttrs::default();
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("command")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("name") {
                out.name = Some(meta.value()?.parse::<LitStr>()?.value());
            } else if meta.path.is_ident("about") {
                out.about = Some(meta.value()?.parse::<LitStr>()?.value());
            } else if meta.path.is_ident("alias") {
                out.aliases.push(meta.value()?.parse::<LitStr>()?.value());
            } else if meta.path.is_ident("visible_alias") {
                out.visible_aliases
                    .push(meta.value()?.parse::<LitStr>()?.value());
            } else if meta.path.is_ident("handler") {
                out.handler = Some(meta.value()?.parse::<Path>()?);
            } else if meta.path.is_ident("flatten") {
                out.flatten = true;
            } else if meta.path.is_ident("crate") {
                let _ = meta.value()?.parse::<Path>()?;
            } else {
                return Err(meta.error(UNKNOWN_COMMAND_KEY));
            }
            Ok(())
        })?;
    }
    Ok(out)
}

fn parse_field_attrs(field: &syn::Field) -> syn::Result<FieldAttrs> {
    let mut out = FieldAttrs::default();
    for attr in &field.attrs {
        if attr.path().is_ident("arg") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("short") {
                    out.short_set = true;
                    if meta.input.peek(syn::Token![=]) {
                        out.short = Some(meta.value()?.parse::<LitChar>()?.value());
                    }
                } else if meta.path.is_ident("long") {
                    out.long_set = true;
                    if meta.input.peek(syn::Token![=]) {
                        out.long = Some(meta.value()?.parse::<LitStr>()?.value());
                    }
                } else if meta.path.is_ident("global") {
                    out.global = if meta.input.peek(syn::Token![=]) {
                        meta.value()?.parse::<syn::LitBool>()?.value
                    } else {
                        true
                    };
                } else if meta.path.is_ident("default_value_t") {
                    out.default = Some(if meta.input.peek(syn::Token![=]) {
                        meta.value()?.parse::<Expr>()?
                    } else {
                        parse_quote!(Default::default())
                    });
                } else if meta.path.is_ident("value_enum") {
                    out.value_enum = true;
                } else if meta.path.is_ident("value_name") {
                    out.value_name = Some(meta.value()?.parse::<LitStr>()?.value());
                } else if meta.path.is_ident("help") {
                    out.help = Some(meta.value()?.parse::<LitStr>()?.value());
                } else if meta.path.is_ident("alias") {
                    out.aliases.push(meta.value()?.parse::<LitStr>()?.value());
                } else if meta.path.is_ident("visible_alias") {
                    out.visible_aliases
                        .push(meta.value()?.parse::<LitStr>()?.value());
                } else if meta.path.is_ident("required") {
                    out.required = Some(if meta.input.peek(syn::Token![=]) {
                        meta.value()?.parse::<syn::LitBool>()?.value
                    } else {
                        true
                    });
                } else if meta.path.is_ident("allow_hyphen_values") {
                    out.allow_hyphen_values = if meta.input.peek(syn::Token![=]) {
                        meta.value()?.parse::<syn::LitBool>()?.value
                    } else {
                        true
                    };
                } else if meta.path.is_ident("action") {
                    let action = meta.value()?.parse::<Path>()?;
                    let last = action
                        .segments
                        .last()
                        .map(|segment| segment.ident.to_string());
                    match last.as_deref() {
                        Some("Count") => out.action_count = true,
                        Some("SetFalse") => out.action_set_false = true,
                        Some("Set") | Some("SetTrue") | Some("Append") => {}
                        _ => {
                            return Err(meta.error(
                                "unsupported action; expected one of Set, SetTrue, SetFalse, Count, Append",
                            ))
                        }
                    }
                } else {
                    return Err(meta.error(UNKNOWN_ARG_KEY));
                }
                Ok(())
            })?;
        } else if attr.path().is_ident("command") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("subcommand") {
                    out.subcommand = true;
                } else if meta.path.is_ident("flatten") {
                    out.flatten = true;
                } else {
                    return Err(meta.error(
                        "unrecognized `command` key on a field; expected `subcommand` or `flatten`",
                    ));
                }
                Ok(())
            })?;
        }
    }
    Ok(out)
}

fn parse_dispatch_context(attrs: &[Attribute]) -> syn::Result<Path> {
    let mut context = None;
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("dispatch")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("context") {
                context = Some(meta.value()?.parse::<Path>()?);
            }
            Ok(())
        })?;
    }
    context.ok_or_else(|| {
        syn::Error::new(
            proc_macro2::Span::call_site(),
            "missing #[dispatch(context = Type)]",
        )
    })
}

/// Resolve the path to the runtime crate, allowing `#[command(crate = ...)]` to override it.
///
/// Needed when the dependency is renamed in `Cargo.toml`, since generated code cannot otherwise
/// name the crate.
fn crate_path(attrs: &[Attribute]) -> syn::Result<Path> {
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("command")) {
        let mut found = None;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("crate") {
                found = Some(meta.value()?.parse::<Path>()?);
            } else if meta.input.peek(syn::Token![=]) {
                // Consume the value of keys handled elsewhere so parsing can continue.
                let _ = meta.value()?.parse::<Expr>();
            }
            Ok(())
        })?;
        if let Some(path) = found {
            return Ok(path);
        }
    }
    Ok(parse_quote!(::microtun_cli))
}

fn validate_generics(generics: &Generics) -> syn::Result<Option<syn::Lifetime>> {
    let mut lifetime = None;
    for param in &generics.params {
        match param {
            syn::GenericParam::Lifetime(value) if lifetime.is_none() => {
                lifetime = Some(value.lifetime.clone());
            }
            syn::GenericParam::Lifetime(value) => {
                return Err(syn::Error::new_spanned(
                    value,
                    "microtun-cli v0.1 supports at most one lifetime parameter",
                ));
            }
            other => {
                return Err(syn::Error::new_spanned(
                    other,
                    "microtun-cli v0.1 derives do not support type or const generics",
                ));
            }
        }
    }
    Ok(lifetime)
}

fn impl_generics_with_cli(input: &DeriveInput) -> syn::Result<(Generics, syn::Lifetime)> {
    let existing = validate_generics(&input.generics)?;
    let mut generics = input.generics.clone();
    let lifetime = match existing {
        Some(lifetime) => lifetime,
        None => {
            let lifetime: syn::Lifetime = parse_quote!('cli);
            generics.params.insert(0, parse_quote!('cli));
            lifetime
        }
    };
    Ok((generics, lifetime))
}

fn option_inner(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else { return None };
    let segment = path.path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    args.args.iter().find_map(|arg| match arg {
        GenericArgument::Type(ty) => Some(ty),
        _ => None,
    })
}

fn repeated_vec_inner(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else { return None };
    let segment = path.path.segments.last()?;
    if segment.ident != "Vec" {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };

    let mut ty_arg = None;
    let mut const_args = 0usize;
    let mut unsupported = false;
    for arg in &args.args {
        match arg {
            GenericArgument::Type(ty) if ty_arg.is_none() => ty_arg = Some(ty),
            GenericArgument::Const(_) => const_args += 1,
            _ => unsupported = true,
        }
    }

    if unsupported || const_args > 1 {
        return None;
    }

    // One type argument is `alloc::vec::Vec<T>`; one type plus one const argument is
    // `heapless::Vec<T, N>`. The generated code relies on the runtime's `RepeatedArg` trait,
    // which gates the allocating implementation behind the `alloc` feature.
    ty_arg
}

fn is_bool(ty: &Type) -> bool {
    matches!(ty, Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "bool"))
}

fn staticize_type(ty: &Type) -> Type {
    let mut out = ty.clone();
    if let Type::Reference(reference) = &mut out {
        if reference.lifetime.is_some() {
            reference.lifetime = Some(parse_quote!('static));
        }
        *reference.elem = staticize_type(reference.elem.as_ref());
    }
    if let Type::Path(path) = &mut out {
        for segment in &mut path.path.segments {
            if let PathArguments::AngleBracketed(args) = &mut segment.arguments {
                for arg in &mut args.args {
                    match arg {
                        GenericArgument::Lifetime(lifetime) => *lifetime = parse_quote!('static),
                        GenericArgument::Type(ty) => *ty = staticize_type(ty),
                        _ => {}
                    }
                }
            }
        }
    }
    out
}

fn field_names(field: &syn::Field, attrs: &FieldAttrs) -> (Option<String>, Option<char>) {
    let ident = field.ident.as_ref().expect("named field").to_string();
    let long = attrs
        .long_set
        .then(|| attrs.long.clone().unwrap_or_else(|| ident.to_kebab_case()));
    let short = attrs.short_set.then(|| {
        attrs
            .short
            .unwrap_or_else(|| ident.chars().next().unwrap_or('x'))
    });
    (long, short)
}

fn value_type(ty: &Type) -> &Type {
    if let Some(inner) = option_inner(ty) {
        inner
    } else if let Some(inner) = repeated_vec_inner(ty) {
        inner
    } else {
        ty
    }
}

fn default_help_text(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(value) => match &value.lit {
            Lit::Str(value) => Some(value.value()),
            Lit::Char(value) => Some(value.value().to_string()),
            Lit::Byte(value) => Some(value.value().to_string()),
            Lit::Int(value) => Some(value.base10_digits().to_owned()),
            Lit::Float(value) => Some(value.base10_digits().to_owned()),
            Lit::Bool(value) => Some(value.value.to_string()),
            _ => None,
        },
        Expr::Unary(value) if matches!(value.op, syn::UnOp::Neg(_)) => {
            default_help_text(&value.expr).map(|text| format!("-{text}"))
        }
        Expr::Paren(value) => default_help_text(&value.expr),
        Expr::Group(value) => default_help_text(&value.expr),
        _ => None,
    }
}

fn field_schema(
    field: &syn::Field,
    krate: &Path,
    lifetime: &syn::Lifetime,
) -> syn::Result<proc_macro2::TokenStream> {
    let attrs = parse_field_attrs(field)?;
    let ident = field
        .ident
        .as_ref()
        .ok_or_else(|| syn::Error::new_spanned(field, "expected named field"))?;
    let ident_string = ident.to_string();
    let help = attrs
        .help
        .clone()
        .unwrap_or_else(|| doc_string(&field.attrs));
    let help_lit = LitStr::new(&help, ident.span());

    if attrs.subcommand {
        return Ok(quote! {});
    }
    if attrs.flatten {
        let ty = &field.ty;
        return Ok(quote! {
            #krate::ArgSpec {
                name: #ident_string,
                help: #help_lit,
                kind: #krate::ArgKind::Flatten,
                children: <#ty as #krate::Args<#lifetime>>::ARGS,
                ..#krate::ArgSpec::DEFAULT
            }
        });
    }

    let (long, short) = field_names(field, &attrs);
    let long_tokens = match long {
        Some(value) => quote! { Some(#value) },
        None => quote! { None },
    };
    let short_tokens = match short {
        Some(value) => quote! { Some(#value) },
        None => quote! { None },
    };
    let is_option = attrs.long_set || attrs.short_set;
    let optional = option_inner(&field.ty).is_some();
    let repeated = repeated_vec_inner(&field.ty).is_some();
    let flag = is_option && (is_bool(&field.ty) || attrs.action_count || attrs.action_set_false);
    if attrs.default.is_some() && (flag || optional || repeated) {
        return Err(syn::Error::new_spanned(
            field,
            "`default_value_t` cannot be honoured on a flag, an `Option<..>` field, or a repeated \
             field, and would otherwise be advertised in `--help` without taking effect; drop the \
             attribute, or use a plain value type so the default can be applied",
        ));
    }
    let required = attrs
        .required
        .unwrap_or(!flag && !optional && !repeated && attrs.default.is_none());
    let aliases = &attrs.aliases;
    let visible_aliases = &attrs.visible_aliases;
    let kind = if flag {
        quote! { #krate::ArgKind::Flag }
    } else if is_option {
        quote! { #krate::ArgKind::Option }
    } else {
        quote! { #krate::ArgKind::Positional }
    };
    let value_name = attrs
        .value_name
        .clone()
        .unwrap_or_else(|| ident_string.to_shouty_snake_case());
    let default_text = attrs.default.as_ref().and_then(default_help_text);
    let default = match &default_text {
        Some(text) => quote! { Some(#text) },
        None => quote! { None },
    };
    let values_ty = value_type(&field.ty);
    let global = attrs.global;
    let action = if attrs.action_count {
        quote! { #krate::ArgAction::Count }
    } else if attrs.action_set_false {
        quote! { #krate::ArgAction::SetFalse }
    } else if flag {
        quote! { #krate::ArgAction::SetTrue }
    } else if repeated {
        quote! { #krate::ArgAction::Append }
    } else {
        quote! { #krate::ArgAction::Set }
    };
    let values = if attrs.value_enum {
        quote! { <#values_ty as #krate::ValueEnum>::VALUES }
    } else {
        quote! { &[] }
    };
    let allow_hyphen = attrs.allow_hyphen_values;

    Ok(quote! {
        #krate::ArgSpec {
            name: #ident_string,
            help: #help_lit,
            short: #short_tokens,
            long: #long_tokens,
            aliases: &[#(#aliases),*],
            visible_aliases: &[#(#visible_aliases),*],
            value_name: #value_name,
            required: #required,
            global: #global,
            default: #default,
            kind: #kind,
            action: #action,
            allow_hyphen_values: #allow_hyphen,
            values: #values,
            ..#krate::ArgSpec::DEFAULT
        }
    })
}

fn parse_field_expr(
    field: &syn::Field,
    krate: &Path,
    lifetime: &syn::Lifetime,
) -> syn::Result<proc_macro2::TokenStream> {
    let attrs = parse_field_attrs(field)?;
    let ident = field
        .ident
        .as_ref()
        .ok_or_else(|| syn::Error::new_spanned(field, "expected named field"))?;
    let label = ident.to_string();
    let ty = &field.ty;

    if attrs.subcommand {
        return Ok(quote! {
            <#ty as #krate::Subcommand<#lifetime>>::parse_subcommand(cursor)?
        });
    }
    if attrs.flatten {
        return Ok(quote! {
            <#ty as #krate::Args<#lifetime>>::parse_args(cursor)?
        });
    }

    let (long, short) = field_names(field, &attrs);
    let long_tokens = match long {
        Some(value) => quote! { Some(#value) },
        None => quote! { None },
    };
    let short_tokens = match short {
        Some(value) => quote! { Some(#value) },
        None => quote! { None },
    };
    let is_option = attrs.long_set || attrs.short_set;
    let aliases = &attrs.aliases;
    let visible_aliases = &attrs.visible_aliases;
    let required_option = attrs.required.unwrap_or(false);
    let allow_hyphen = attrs.allow_hyphen_values;

    if is_option && attrs.action_count {
        if !matches!(ty, Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "u8"))
        {
            return Err(syn::Error::new_spanned(
                ty,
                "ArgAction::Count currently requires a u8 field",
            ));
        }
        return Ok(quote! {{
            let value = cursor.take_flag_count_aliases_with_visible(
                #long_tokens,
                #short_tokens,
                &[#(#aliases),*],
                &[#(#visible_aliases),*],
            );
            if #required_option && value == 0 {
                return Err(#krate::ParseError::for_argument(
                    #krate::ParseErrorKind::MissingArgument,
                    #label,
                ));
            }
            value
        }});
    }

    if is_option && attrs.action_set_false && is_bool(ty) {
        return Ok(quote! {{
            let present = cursor.take_flag_aliases_with_visible(
                #long_tokens,
                #short_tokens,
                &[#(#aliases),*],
                &[#(#visible_aliases),*],
            );
            if #required_option && !present {
                return Err(#krate::ParseError::for_argument(
                    #krate::ParseErrorKind::MissingArgument,
                    #label,
                ));
            }
            !present
        }});
    }

    if is_option && is_bool(ty) {
        return Ok(quote! {{
            let present = cursor.take_flag_aliases_with_visible(
                #long_tokens,
                #short_tokens,
                &[#(#aliases),*],
                &[#(#visible_aliases),*],
            );
            if #required_option && !present {
                return Err(#krate::ParseError::for_argument(
                    #krate::ParseErrorKind::MissingArgument,
                    #label,
                ));
            }
            present
        }});
    }

    if let Some(inner) = option_inner(ty) {
        if is_option {
            return Ok(quote! {
                match cursor.take_option_aliases_with_visible(#long_tokens, #short_tokens, &[#(#aliases),*], &[#(#visible_aliases),*], #label, #allow_hyphen)? {
                    Some(raw) => Some(<#inner as #krate::FromArg<#lifetime>>::from_arg(raw)
                        .map_err(|error| #krate::ParseError::invalid_value(
                            #label,
                            error.expected,
                        ))?),
                    None => {
                        if #required_option {
                            return Err(#krate::ParseError::for_argument(
                                #krate::ParseErrorKind::MissingArgument,
                                #label,
                            ));
                        }
                        None
                    },
                }
            });
        }
        return Ok(quote! {
            match cursor.take_positional()? {
                Some(raw) => Some(<#inner as #krate::FromArg<#lifetime>>::from_arg(raw)
                    .map_err(|error| #krate::ParseError::invalid_value(
                        #label,
                        error.expected,
                    ))?),
                None => {
                    if #required_option {
                        return Err(#krate::ParseError::for_argument(
                            #krate::ParseErrorKind::MissingArgument,
                            #label,
                        ));
                    }
                    None
                },
            }
        });
    }

    if let Some(inner) = repeated_vec_inner(ty) {
        if is_option {
            return Ok(quote! {{
                let mut values = <#ty as #krate::parse::RepeatedArg<#inner>>::new();
                while let Some(raw) = cursor.take_option_aliases_with_visible(#long_tokens, #short_tokens, &[#(#aliases),*], &[#(#visible_aliases),*], #label, #allow_hyphen)? {
                    let value = <#inner as #krate::FromArg<#lifetime>>::from_arg(raw)
                        .map_err(|error| #krate::ParseError::invalid_value(
                            #label,
                            error.expected,
                        ))?;
                    if !<#ty as #krate::parse::RepeatedArg<#inner>>::push_value(&mut values, value) {
                        return Err(#krate::ParseError::for_argument(
                            #krate::ParseErrorKind::TooManyValues,
                            #label,
                        ));
                    }
                }
                if #required_option && values.is_empty() {
                    return Err(#krate::ParseError::for_argument(
                        #krate::ParseErrorKind::MissingArgument,
                        #label,
                    ));
                }
                values
            }});
        }
        return Ok(quote! {{
            let mut values = <#ty as #krate::parse::RepeatedArg<#inner>>::new();
            while let Some(raw) = cursor.take_positional()? {
                let value = <#inner as #krate::FromArg<#lifetime>>::from_arg(raw)
                    .map_err(|error| #krate::ParseError::invalid_value(
                        #label,
                        error.expected,
                    ))?;
                if !<#ty as #krate::parse::RepeatedArg<#inner>>::push_value(&mut values, value) {
                    return Err(#krate::ParseError::for_argument(
                        #krate::ParseErrorKind::TooManyValues,
                        #label,
                    ));
                }
            }
            if #required_option && values.is_empty() {
                return Err(#krate::ParseError::for_argument(
                    #krate::ParseErrorKind::MissingArgument,
                    #label,
                ));
            }
            values
        }});
    }

    let parse_value = quote! {
        <#ty as #krate::FromArg<#lifetime>>::from_arg(raw)
            .map_err(|error| #krate::ParseError::invalid_value(
                #label,
                error.expected,
            ))?
    };
    let missing = match &attrs.default {
        Some(default) => quote! { #default },
        None => quote! {
            return Err(#krate::ParseError::for_argument(
                #krate::ParseErrorKind::MissingArgument,
                #label,
            ))
        },
    };

    if is_option {
        Ok(quote! {
            match cursor.take_option_aliases_with_visible(#long_tokens, #short_tokens, &[#(#aliases),*], &[#(#visible_aliases),*], #label, #allow_hyphen)? {
                Some(raw) => #parse_value,
                None => #missing,
            }
        })
    } else {
        Ok(quote! {
            match cursor.take_positional()? {
                Some(raw) => #parse_value,
                None => #missing,
            }
        })
    }
}

fn named_field_parts(
    fields: &syn::FieldsNamed,
    krate: &Path,
    lifetime: &syn::Lifetime,
) -> syn::Result<(
    Vec<proc_macro2::TokenStream>,
    Vec<proc_macro2::TokenStream>,
    Option<Type>,
)> {
    let mut parsed = Vec::new();
    let mut schema = Vec::new();
    let mut subcommand_ty = None;

    let mut longs = NameSet::default();
    let mut shorts = NameSet::default();
    let mut subcommand_field = None;

    let mut ordered: Vec<(&syn::Field, u8)> = Vec::new();
    for field in &fields.named {
        let attrs = parse_field_attrs(field)?;

        if attrs.subcommand {
            if subcommand_field.is_some() {
                return Err(syn::Error::new_spanned(
                    field,
                    "only one `#[command(subcommand)]` field is supported",
                ));
            }
            subcommand_field = Some(field);
            subcommand_ty = Some(field.ty.clone());
        }

        if !attrs.subcommand && !attrs.flatten {
            let (long, short) = field_names(field, &attrs);
            if let Some(long) = long {
                longs.insert(format!("--{long}"), field)?;
            }
            for alias in attrs.aliases.iter().chain(attrs.visible_aliases.iter()) {
                longs.insert(format!("--{alias}"), field)?;
            }
            if let Some(short) = short {
                shorts.insert(format!("-{short}"), field)?;
            }
        }

        let rank = if attrs.subcommand {
            3
        } else if attrs.long_set || attrs.short_set {
            0
        } else if attrs.flatten {
            // Flattened groups may contribute options, which must be claimed before any
            // positional is taken, so they are parsed ahead of this struct's own positionals.
            1
        } else {
            2
        };
        ordered.push((field, rank));
    }
    ordered.sort_by_key(|(_, rank)| *rank);

    for (field, _) in ordered {
        let spec = field_schema(field, krate, lifetime)?;
        if !spec.is_empty() {
            schema.push(spec);
        }
        let ident = field.ident.as_ref().unwrap();
        let expr = parse_field_expr(field, krate, lifetime)?;
        parsed.push(quote! { let #ident = #expr; });
    }

    Ok((parsed, schema, subcommand_ty))
}

fn args_impl(
    input: &DeriveInput,
    data: &DataStruct,
    krate: &Path,
) -> syn::Result<proc_macro2::TokenStream> {
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new_spanned(
            &data.fields,
            "Args/Parser structs must use named fields",
        ));
    };
    let (impl_generics, lifetime) = impl_generics_with_cli(input)?;
    let (impl_g, _, where_clause) = impl_generics.split_for_impl();
    let (_, ty_g, _) = input.generics.split_for_impl();
    let name = &input.ident;
    let (parsed, schema, _) = named_field_parts(fields, krate, &lifetime)?;
    let idents: Vec<_> = fields
        .named
        .iter()
        .map(|field| field.ident.as_ref().unwrap())
        .collect();

    Ok(quote! {
        #[allow(clippy::needless_update)]
        impl #impl_g #krate::Args<#lifetime> for #name #ty_g #where_clause {
            const ARGS: &'static [#krate::ArgSpec] = &[#(#schema),*];

            fn parse_args(
                cursor: &mut #krate::ArgCursor<'_, #lifetime>,
            ) -> Result<Self, #krate::ParseError> {
                cursor.declare_value_shorts(Self::ARGS);
                #(#parsed)*
                Ok(Self { #(#idents),* })
            }
        }
    })
}

fn expand_args(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    validate_generics(&input.generics)?;
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "Args can only be derived for structs",
        ));
    };
    let krate = crate_path(&input.attrs)?;
    args_impl(&input, data, &krate)
}

fn subcommand_impl(
    input: &DeriveInput,
    data: &DataEnum,
    krate: &Path,
) -> syn::Result<proc_macro2::TokenStream> {
    let (impl_generics, lifetime) = impl_generics_with_cli(input)?;
    let (impl_g, _, where_clause) = impl_generics.split_for_impl();
    let (_, ty_g, _) = input.generics.split_for_impl();
    let name = &input.ident;

    let mut parse_arms = Vec::new();
    // Flattened groups are tried only after every literal name of this enum, so a container
    // can shadow a name it inherits rather than the inherited name winning by declaration order.
    let mut flatten_arms = Vec::new();
    let mut specs = Vec::new();
    let mut names = NameSet::default();

    for variant in &data.variants {
        let v_ident = &variant.ident;
        let attrs = parse_command_attrs(&variant.attrs)?;

        if attrs.flatten {
            if attrs.name.is_some()
                || !attrs.aliases.is_empty()
                || !attrs.visible_aliases.is_empty()
            {
                return Err(syn::Error::new_spanned(
                    variant,
                    "a #[command(flatten)] variant contributes no name of its own, \
                     so `name`, `alias`, and `visible_alias` do not apply",
                ));
            }
            let Fields::Unnamed(fields) = &variant.fields else {
                return Err(syn::Error::new_spanned(
                    &variant.fields,
                    "#[command(flatten)] variants must be a tuple variant holding one Subcommand type",
                ));
            };
            if fields.unnamed.len() != 1 {
                return Err(syn::Error::new_spanned(
                    fields,
                    "#[command(flatten)] variants must contain exactly one Subcommand type",
                ));
            }
            let ty = &fields.unnamed.first().unwrap().ty;
            flatten_arms.push(quote! {
                if let Some(inner) =
                    <#ty as #krate::Subcommand<#lifetime>>::parse_named(cursor, command)?
                {
                    return Ok(Some(Self::#v_ident(inner)));
                }
            });
            specs.push(quote! {
                #krate::CommandSpec {
                    flatten: true,
                    subcommands: <#ty as #krate::Subcommand<#lifetime>>::COMMANDS,
                    ..#krate::CommandSpec::DEFAULT
                }
            });
            continue;
        }

        let command_name = attrs
            .name
            .clone()
            .unwrap_or_else(|| v_ident.to_string().to_kebab_case());
        names.insert(command_name.clone(), variant)?;
        for alias in attrs.aliases.iter().chain(attrs.visible_aliases.iter()) {
            names.insert(alias.clone(), variant)?;
        }
        let about = attrs.about.unwrap_or_else(|| doc_string(&variant.attrs));
        let aliases = attrs.aliases;
        let visible_aliases = attrs.visible_aliases;
        let alias_checks = aliases
            .iter()
            .chain(visible_aliases.iter())
            .map(|alias| quote! { || command == #alias });
        let alias_specs = aliases.iter();
        let visible_alias_specs = visible_aliases.iter();

        match &variant.fields {
            Fields::Unit => {
                parse_arms.push(quote! {
                    if command == #command_name #(#alias_checks)* {
                        return Ok(Some(Self::#v_ident));
                    }
                });
                specs.push(quote! {
                    #krate::CommandSpec {
                        name: #command_name,
                        about: #about,
                        aliases: &[#(#alias_specs),*],
                        visible_aliases: &[#(#visible_alias_specs),*],
                        ..#krate::CommandSpec::DEFAULT
                    }
                });
            }
            Fields::Named(fields) => {
                let (parsed, schema, subcommand_ty) = named_field_parts(fields, krate, &lifetime)?;
                let idents: Vec<_> = fields
                    .named
                    .iter()
                    .map(|field| field.ident.as_ref().unwrap())
                    .collect();
                let nested = match &subcommand_ty {
                    Some(ty) => {
                        quote! { <#ty as #krate::Subcommand<#lifetime>>::COMMANDS }
                    }
                    None => quote! { &[] },
                };
                parse_arms.push(quote! {
                    if command == #command_name #(#alias_checks)* {
                        #(#parsed)*
                        return Ok(Some(Self::#v_ident { #(#idents),* }));
                    }
                });
                specs.push(quote! {
                    #krate::CommandSpec {
                        name: #command_name,
                        about: #about,
                        aliases: &[#(#alias_specs),*],
                        visible_aliases: &[#(#visible_alias_specs),*],
                        args: &[#(#schema),*],
                        subcommands: #nested,
                        ..#krate::CommandSpec::DEFAULT
                    }
                });
            }
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                let ty = &fields.unnamed.first().unwrap().ty;
                parse_arms.push(quote! {
                    if command == #command_name #(#alias_checks)* {
                        let args = <#ty as #krate::Args<#lifetime>>::parse_args(cursor)?;
                        return Ok(Some(Self::#v_ident(args)));
                    }
                });
                specs.push(quote! {
                    #krate::CommandSpec {
                        name: #command_name,
                        about: #about,
                        aliases: &[#(#alias_specs),*],
                        visible_aliases: &[#(#visible_alias_specs),*],
                        args: <#ty as #krate::Args<#lifetime>>::ARGS,
                        ..#krate::CommandSpec::DEFAULT
                    }
                });
            }
            Fields::Unnamed(fields) => {
                return Err(syn::Error::new_spanned(
                    fields,
                    "tuple subcommands must contain exactly one Args type",
                ));
            }
        }
    }

    Ok(quote! {
        #[allow(clippy::needless_update)]
        impl #impl_g #krate::Subcommand<#lifetime> for #name #ty_g #where_clause {
            const COMMANDS: &'static [#krate::CommandSpec] = &[#(#specs),*];

            fn parse_named(
                cursor: &mut #krate::ArgCursor<'_, #lifetime>,
                command: &#lifetime str,
            ) -> Result<Option<Self>, #krate::ParseError> {
                #(#parse_arms)*
                #(#flatten_arms)*
                Ok(None)
            }
        }
    })
}

fn expand_subcommand(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    validate_generics(&input.generics)?;
    let Data::Enum(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "Subcommand can only be derived for enums",
        ));
    };
    let krate = crate_path(&input.attrs)?;
    subcommand_impl(&input, data, &krate)
}

fn expand_parser(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let lifetime = validate_generics(&input.generics)?;
    let krate = &crate_path(&input.attrs)?;
    let attrs = parse_container_attrs(&input.attrs)?;
    let name = &input.ident;
    let vis = &input.vis;
    let marker = format_ident!("{}Parser", name);
    let root_name = attrs
        .name
        .unwrap_or_else(|| name.to_string().to_kebab_case());
    let about = attrs.about.unwrap_or_else(|| doc_string(&input.attrs));
    let version = match attrs.version {
        Some(version) => quote! { Some(#version) },
        None => quote! { None },
    };
    let parsed_ty = if lifetime.is_some() {
        quote! { #name<'cli> }
    } else {
        quote! { #name }
    };
    let static_ty: Type = if lifetime.is_some() {
        parse_quote!(#name<'static>)
    } else {
        parse_quote!(#name)
    };

    match &input.data {
        Data::Enum(data) => {
            let subcommand = subcommand_impl(&input, data, krate)?;
            Ok(quote! {
                #subcommand

                #[derive(Clone, Copy, Debug, Default)]
                #vis struct #marker;

                #[allow(clippy::needless_update)]
                impl #krate::ParserFamily for #marker {
                    type Parsed<'cli> = #parsed_ty;
                    const ROOT: #krate::RootSpec = #krate::RootSpec {
                        name: #root_name,
                        about: #about,
                        version: #version,
                        commands: <#static_ty as #krate::Subcommand<'static>>::COMMANDS,
                        ..#krate::RootSpec::DEFAULT
                    };

                    fn parse<'cli>(
                        line: &'cli mut [u8],
                        len: usize,
                    ) -> Result<Self::Parsed<'cli>, #krate::ParseError> {
                        let lexed = #krate::lexer::lex(line, len)?;
                        if lexed.is_empty() {
                            return Err(#krate::ParseError::new(
                                #krate::ParseErrorKind::Empty,
                            ));
                        }
                        let mut cursor = #krate::ArgCursor::new(&lexed);
                        let parsed = <Self::Parsed<'cli> as #krate::Subcommand<'cli>>::parse_subcommand(&mut cursor)?;
                        cursor.finish()?;
                        Ok(parsed)
                    }
                }
            })
        }
        Data::Struct(data) => {
            let args = args_impl(&input, data, krate)?;
            let Fields::Named(fields) = &data.fields else {
                return Err(syn::Error::new_spanned(
                    &data.fields,
                    "Parser structs must use named fields",
                ));
            };
            let mut root_commands = quote! { &[] };
            for field in &fields.named {
                let fattrs = parse_field_attrs(field)?;
                if fattrs.subcommand {
                    let static_field_ty = staticize_type(&field.ty);
                    root_commands = quote! {
                        <#static_field_ty as #krate::Subcommand<'static>>::COMMANDS
                    };
                    break;
                }
            }
            Ok(quote! {
                #args

                #[derive(Clone, Copy, Debug, Default)]
                #vis struct #marker;

                #[allow(clippy::needless_update)]
                impl #krate::ParserFamily for #marker {
                    type Parsed<'cli> = #parsed_ty;
                    const ROOT: #krate::RootSpec = #krate::RootSpec {
                        name: #root_name,
                        about: #about,
                        version: #version,
                        args: <#static_ty as #krate::Args<'static>>::ARGS,
                        commands: #root_commands,
                        ..#krate::RootSpec::DEFAULT
                    };

                    fn parse<'cli>(
                        line: &'cli mut [u8],
                        len: usize,
                    ) -> Result<Self::Parsed<'cli>, #krate::ParseError> {
                        let lexed = #krate::lexer::lex(line, len)?;
                        if lexed.is_empty() {
                            return Err(#krate::ParseError::new(
                                #krate::ParseErrorKind::Empty,
                            ));
                        }
                        let mut cursor = #krate::ArgCursor::new(&lexed);
                        let parsed = <Self::Parsed<'cli> as #krate::Args<'cli>>::parse_args(&mut cursor)?;
                        cursor.finish()?;
                        Ok(parsed)
                    }
                }
            })
        }
        Data::Union(data) => Err(syn::Error::new_spanned(
            data.union_token,
            "Parser cannot be derived for unions",
        )),
    }
}

fn expand_value_enum(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    validate_generics(&input.generics)?;
    let krate = &crate_path(&input.attrs)?;
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "ValueEnum must not be generic",
        ));
    }
    let Data::Enum(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "ValueEnum can only be derived for enums",
        ));
    };
    let name = &input.ident;
    let mut specs = Vec::new();
    let mut parse_arms = Vec::new();
    let mut expected_values = Vec::<String>::new();

    for variant in &data.variants {
        if !matches!(variant.fields, Fields::Unit) {
            return Err(syn::Error::new_spanned(
                &variant.fields,
                "ValueEnum variants must be unit variants",
            ));
        }
        let ident = &variant.ident;
        let mut value_name = ident.to_string().to_kebab_case();
        let mut aliases = Vec::<String>::new();
        let mut visible_aliases = Vec::<String>::new();
        for attr in variant
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("value"))
        {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    value_name = meta.value()?.parse::<LitStr>()?.value();
                } else if meta.path.is_ident("alias") {
                    aliases.push(meta.value()?.parse::<LitStr>()?.value());
                } else if meta.path.is_ident("visible_alias") {
                    visible_aliases.push(meta.value()?.parse::<LitStr>()?.value());
                } else {
                    return Err(meta.error(
                        "unrecognized `value` key; expected `name`, `alias`, or `visible_alias`",
                    ));
                }
                Ok(())
            })?;
        }
        let help = doc_string(&variant.attrs);
        expected_values.push(value_name.clone());
        let checks = aliases
            .iter()
            .chain(visible_aliases.iter())
            .map(|alias| quote! { || value == #alias });
        parse_arms.push(quote! {
            if value == #value_name #(#checks)* {
                return Ok(Self::#ident);
            }
        });
        specs.push(quote! {
            #krate::ValueSpec {
                name: #value_name,
                help: #help,
                aliases: &[#(#aliases),*],
                visible_aliases: &[#(#visible_aliases),*],
                ..#krate::ValueSpec::DEFAULT
            }
        });
    }

    let expected = format!("one of: {}", expected_values.join(", "));

    Ok(quote! {
        #[allow(clippy::needless_update)]
        impl #krate::ValueEnum for #name {
            const VALUES: &'static [#krate::ValueSpec] = &[#(#specs),*];
        }

        impl<'cli> #krate::FromArg<'cli> for #name {
            fn from_arg(value: &'cli str) -> Result<Self, #krate::ValueError> {
                #(#parse_arms)*
                Err(#krate::ValueError::new(#expected))
            }
        }
    })
}

fn expand_dispatch(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    validate_generics(&input.generics)?;
    let krate = &crate_path(&input.attrs)?;
    let context = parse_dispatch_context(&input.attrs)?;
    let name = &input.ident;
    let (impl_g, ty_g, where_clause) = input.generics.split_for_impl();

    match &input.data {
        Data::Struct(data) => {
            let Fields::Named(fields) = &data.fields else {
                return Err(syn::Error::new_spanned(
                    &data.fields,
                    "Dispatch structs must use named fields",
                ));
            };
            let nested = fields
                .named
                .iter()
                .find_map(|field| {
                    parse_field_attrs(field)
                        .ok()
                        .filter(|attrs| attrs.subcommand)
                        .and(field.ident.as_ref())
                })
                .ok_or_else(|| {
                    syn::Error::new_spanned(
                        fields,
                        "Dispatch on a struct requires a #[command(subcommand)] field",
                    )
                })?;
            Ok(quote! {
                impl #impl_g #krate::Dispatch<#context> for #name #ty_g #where_clause {
                    async fn dispatch<W: ::embedded_io_async::Write<Error = #krate::ErrorKind> + ?Sized>(
                        self,
                        context: &mut #context,
                        out: &mut W,
                    ) -> Result<(), #krate::Error> {
                        let Self { #nested, .. } = self;
                        #krate::Dispatch::dispatch(#nested, context, out).await
                    }
                }
            })
        }
        Data::Enum(data) => {
            let mut arms = Vec::new();
            for variant in &data.variants {
                let ident = &variant.ident;
                let attrs = parse_command_attrs(&variant.attrs)?;
                match &variant.fields {
                    Fields::Unit => {
                        if let Some(handler) = attrs.handler {
                            arms.push(quote! {
                                Self::#ident => {
                                    #handler(context, out).await?;
                                    Ok(())
                                }
                            });
                        } else {
                            arms.push(quote! { Self::#ident => Err(#krate::Error::NoHandler) });
                        }
                    }
                    Fields::Named(fields) => {
                        let field_idents: Vec<_> = fields
                            .named
                            .iter()
                            .map(|field| field.ident.as_ref().unwrap())
                            .collect();
                        if let Some(handler) = attrs.handler {
                            arms.push(quote! {
                                Self::#ident { #(#field_idents),* } => {
                                    #handler(context, out, #(#field_idents),*).await?;
                                    Ok(())
                                }
                            });
                        } else {
                            let nested = fields.named.iter().find_map(|field| {
                                parse_field_attrs(field)
                                    .ok()
                                    .filter(|attrs| attrs.subcommand)
                                    .and(field.ident.as_ref())
                            });
                            if let Some(nested) = nested {
                                arms.push(quote! {
                                    Self::#ident { #nested, .. } => {
                                        #krate::Dispatch::dispatch(#nested, context, out).await
                                    }
                                });
                            } else {
                                arms.push(quote! {
                                    Self::#ident { .. } => Err(#krate::Error::NoHandler)
                                });
                            }
                        }
                    }
                    Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                        if let Some(handler) = attrs.handler {
                            arms.push(quote! {
                                Self::#ident(args) => {
                                    #handler(context, out, args).await?;
                                    Ok(())
                                }
                            });
                        } else {
                            arms.push(quote! {
                                Self::#ident(args) => #krate::Dispatch::dispatch(args, context, out).await
                            });
                        }
                    }
                    Fields::Unnamed(fields) => {
                        return Err(syn::Error::new_spanned(
                            fields,
                            "tuple dispatch variants must contain one field",
                        ));
                    }
                }
            }

            Ok(quote! {
                impl #impl_g #krate::Dispatch<#context> for #name #ty_g #where_clause {
                    async fn dispatch<W: ::embedded_io_async::Write<Error = #krate::ErrorKind> + ?Sized>(
                        self,
                        context: &mut #context,
                        out: &mut W,
                    ) -> Result<(), #krate::Error> {
                        match self {
                            #(#arms),*
                        }
                    }
                }
            })
        }
        Data::Union(data) => Err(syn::Error::new_spanned(
            data.union_token,
            "Dispatch cannot be derived for unions",
        )),
    }
}
