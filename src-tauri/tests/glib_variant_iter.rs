#![cfg(target_os = "linux")]

use glib::prelude::*;

#[test]
fn patched_variant_str_iter_survives_release_optimization() {
    let variant = glib::Variant::array_from_iter::<String>([
        "hex".to_string().to_variant(),
        "hawk".to_string().to_variant(),
    ]);

    let values: Vec<_> = variant.array_iter_str().unwrap().collect();
    assert_eq!(values, ["hex", "hawk"]);
}
