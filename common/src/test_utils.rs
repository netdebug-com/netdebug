use std::{env, path::Path};

/**
 * Help tests find the testing directory - it's harder than it should be.
 *
 * If we invoke tests via 'cargo test', the base dir is netdebug/libconntrack
 * but if we start it from the vscode debug IDE, it's netdebug
 */

pub fn test_dir(base: &str, f: &str) -> String {
    use std::fs::metadata;
    if metadata(f).is_ok() {
        return f.to_string();
    }
    let p = Path::new(base).join(f);
    if metadata(&p).is_ok() {
        let p = p.into_os_string().to_str().unwrap().to_string();
        p
    } else {
        let cwd = env::current_dir().unwrap();
        panic!(
            "Couldn't find a test_dir for {} from cwd={}",
            f,
            cwd.display()
        );
    }
}
