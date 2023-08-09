pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/**
 * Super helpful HTML macro that will create an element and set all of the attributes
 *
 * /// let div = html!("div", {
 * ///  "name" => "root_div",
 * ///  "id" => "container",
 * ///   /* .... more attributes*/
 * /// })
 * /// assert_eq!(div.get_attribute("name"), Some("root_div");
 * ///
 */

#[macro_export]
macro_rules! html {
    ($e:expr, {$( $k:expr => $v:expr ),* $(,)?}) => {
        {
        (|| -> Result<web_sys::Element, wasm_bindgen::JsValue> {
        let d = web_sys::window().expect("window").document().expect("document");
        let element = d.create_element($e)?;
        $(
            element.set_attribute($k,$v)?;
        )*
        Ok(element)
    })()
    }
    }
}
