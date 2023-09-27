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
 * Modestly helpful HTML macro that will create an element and set all of the attributes
 *
 * /// let div = html!("div", {
 * ///  "name" => "root_div",
 * ///  "id" => "container",
 * ///   /* .... more attributes*/
 * /// });
 * /// assert_eq!(div.get_attribute("name"), Some("root_div");
 * ///
 *
 * Alternatively, can also append children at the end
 * /// let list = html!("ui", {"id = "mylist"},
 * ///      html!("li", {"inner_html" => "item1"}),
 * ///      html!("li", {"inner_html" => "item2"}),
 * ///      html!("li", {"inner_html" => "item3"}),
 * /// );
 * /// assert_eq!(list.children().length(), 3);
 *
 * A smarter person than I would have been able to simplify this into a single case...
 */

#[macro_export]
macro_rules! html {
    // html!("div", {"key"=>"value", ...})
    ($e:expr) => {
        {
        (|| -> Result<web_sys::Element, wasm_bindgen::JsValue> {
        let d = web_sys::window().expect("window").document().expect("document");
        let element = d.create_element($e)?;
        Ok(element)
    })()
    }
    };
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
    };
    // html!("div", {"key"=>"value", ...}, child1, child2, ...)
    ($e:expr, {$( $k:expr => $v:expr ),* $(,)?}, $($c:expr),*) => {
        {
        (|| -> Result<web_sys::Element, wasm_bindgen::JsValue> {
        let d = web_sys::window().expect("window").document().expect("document");
        let element = d.create_element($e)?;
        $(
            element.set_attribute($k,$v)?;
        )*
        $(
            element.append_child(&$c)?;
        )*
        Ok(element)
    })()
    }
    };
}