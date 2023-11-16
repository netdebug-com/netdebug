// Magic to setup tabs and their helpers
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use web_sys::HtmlTextAreaElement;
use web_sys::{Document, Element, HtmlElement};

use crate::consts::*;

use crate::{console_log, log};

pub fn setup_insights_tab(document: &Document, root_div: &Element) -> Result<(), JsValue> {
    let button = create_tabs_button(document, INSIGHTS_TAB, false)?;
    let label = create_tabs_label(document, "Insights", INSIGHTS_TAB)?;
    let div = create_tabs_content(document, INSIGHTS_TAB)?;

    div.set_inner_html("Waiting for probes to finish");

    root_div.append_child(&button)?;
    root_div.append_child(&label)?;
    root_div.append_child(&div)?;
    Ok(())
}
pub fn setup_annotate_tab(document: &Document, root_div: &Element) -> Result<(), JsValue> {
    let button = create_tabs_button(document, ANNOTATE_TAB, false)?;
    let label = create_tabs_label(document, "Annotate", ANNOTATE_TAB)?;
    let div = create_tabs_content(document, ANNOTATE_TAB)?;

    // from https://www.w3schools.com/tags/tryit.asp?filename=tryhtml_textarea
    let form = document.create_element("form")?;
    form.set_id("annotation_form");

    let text_label = document.create_element("label")?;
    text_label.set_inner_html("Tell us about anything you want about this connection");
    text_label.set_attribute("for", ANNOTATE_TEXT_AREA)?;
    let p = document.create_element("p")?;
    p.append_child(&text_label)?;

    let text_area = document
        .create_element("textarea")?
        .dyn_into::<HtmlTextAreaElement>()?;
    text_area.set_id(ANNOTATE_TEXT_AREA);
    text_area.set_attribute("name", "annotation_textarea")?;
    text_area.set_attribute("rows", "10")?;
    text_area.set_attribute("cols", "80")?;
    text_area.set_placeholder(
        r#"<optional but appreciated!>

Please provide any information about your connection
including location, type (wifi, cell phone, etc.), and 
your perception of the performance ("Great!", "really slow!", etc.)

We can guess a lot of this, but it's nice to validate our guesses!
"#,
    );

    let p2 = document.create_element("p")?;

    // NOTE: the 'onclick' function for the button will be setup once the websocket
    // is created; until then it will do nothing
    let input_button = document.create_element("button")?;
    input_button.set_attribute("type", "button")?;
    input_button.set_attribute("value", "Submit Annotation!")?;
    input_button.set_id(ANNOTATE_INPUT_BUTTON);
    input_button.set_inner_html("Submit");
    p2.append_child(&input_button)?;

    form.append_child(&p)?;
    form.append_child(&text_area)?;
    form.append_child(&p2)?;

    div.append_child(&form)?;

    root_div.append_child(&button)?;
    root_div.append_child(&label)?;
    root_div.append_child(&div)?;
    Ok(())
}

pub fn setup_graph_tab(
    document: &Document,
    body: &HtmlElement,
    root_div: &Element,
) -> Result<(), JsValue> {
    let button = create_tabs_button(document, GRAPH_TAB, false)?;
    let label = create_tabs_label(document, "Graph", GRAPH_TAB)?;
    let div = create_tabs_content(document, GRAPH_TAB)?;

    let canvas = document.create_element("canvas").unwrap();
    canvas.set_id("canvas"); // come back if we need manual double buffering
    let (width, height) = calc_height(document, body);
    let width = 9 * width / 10;
    let height = 4 * height / 5;
    console_log!("Setting height to {}, width to {}", height, width);
    canvas.set_attribute("width", format!("{}", width).as_str())?;
    canvas.set_attribute("height", format!("{}", height).as_str())?;

    div.append_child(&canvas)?;

    root_div.append_child(&button)?;
    root_div.append_child(&label)?;
    root_div.append_child(&div)?;
    Ok(())
}

pub fn setup_probes_tab(document: &Document, root_div: &Element) -> Result<(), JsValue> {
    let button = create_tabs_button(document, PROBE_TAB, false)?;
    let label = create_tabs_label(document, "Probes", PROBE_TAB)?;
    let div = create_tabs_content(document, PROBE_TAB)?;

    div.set_inner_html("Waiting for probes!");
    root_div.append_child(&button)?;
    root_div.append_child(&label)?;
    root_div.append_child(&div)?;
    Ok(())
}

pub fn setup_main_tab(document: &Document, root_div: &Element) -> Result<(), JsValue> {
    let button = create_tabs_button(document, MAIN_TAB, true)?;
    let label = create_tabs_label(document, "Summary", MAIN_TAB)?;
    let div = create_tabs_content(document, MAIN_TAB)?;

    /*
     * <label for="file">Downloading progress:</label>
     * <progress id="file" value="32" max="100"> 32% </progress>
     */

    let progress_label = document.create_element("label")?;
    progress_label.set_attribute("for", PROGRESS_METER)?;
    progress_label.set_inner_html("Sending Probes:");

    let progress = document.create_element("progress")?;
    progress.set_id(PROGRESS_METER);
    progress.set_attribute("value", "0")?;
    progress.set_attribute("max", "100")?; // will get overwriten by update

    div.append_child(&progress_label)?;
    div.append_child(&progress)?;
    root_div.append_child(&button)?;
    root_div.append_child(&label)?;
    root_div.append_child(&div)?;
    Ok(())
}

/**
* The CSS magic for tabs REQUIRES that elements are declared in this order:
*  1) radio button with class=tabs__radio
*  2) tab lable    with class=tabs__label
*  3) tab content  with class=tabs__content
 <input type="radio" class="tabs__radio" name="tabs-example" id="tab1" checked>
 <label for="tab1" class="tabs__label">Tab #1</label>
 <div class="tabs__content">
   CONTENT for Tab #1
 </div>
*/

fn create_tabs_content(document: &Document, name: &str) -> Result<Element, JsValue> {
    let div = document.create_element("div")?;
    div.set_class_name("tabs__content");
    div.set_id(name);
    Ok(div)
}

fn create_tabs_label(document: &Document, text: &str, tab: &str) -> Result<Element, JsValue> {
    let label = document.create_element("label")?;
    label.set_class_name("tabs__label");
    label.set_attribute("for", format!("{}__id", tab).as_str())?;
    label.set_inner_html(text);
    Ok(label)
}

fn create_tabs_button(document: &Document, id: &str, checked: bool) -> Result<Element, JsValue> {
    let button = document.create_element("input")?;
    button.set_attribute("type", "radio")?;
    if checked {
        // selected by default
        button.set_attribute("checked", "true")?;
    }
    // all of the buttons in the same group need to share this name
    button.set_attribute("name", "top-level-tabs")?;
    button.set_class_name("tabs__radio");
    button.set_id(format!("{}__id", id).as_str());
    Ok(button)
}

pub fn build_info_div(document: &Document) -> Result<Element, JsValue> {
    let div = document.create_element("div").unwrap();
    div.set_inner_html("Build info:");
    let list = document.create_element("ul")?;
    let list_item = document.create_element("li")?;
    // what date does this show?
    list_item.set_inner_html(format!("Last Modified = {}", document.last_modified()).as_str());
    list.append_child(&list_item)?;
    let list_item = document.create_element("li")?;
    list_item.set_inner_html(format!("GitHash = {}", common_wasm::get_git_hash_version()).as_str());
    list.append_child(&list_item)?;
    div.append_child(&list)?;
    Ok(div)
}

// see https://stackoverflow.com/questions/1145850/how-to-get-height-of-entire-document-with-javascript
// for why height and width are complex to calculate
pub fn calc_height(document: &Document, body: &HtmlElement) -> (i32, i32) {
    let html = document.document_element().unwrap();
    let possible_heights = [
        body.scroll_height(),
        body.offset_height(),
        html.client_height(),
        html.scroll_height(),
    ];
    let possible_widths = [
        body.scroll_width(),
        body.offset_width(),
        html.client_width(),
        html.scroll_width(),
    ];
    (
        *possible_widths.iter().max().unwrap(),
        *possible_heights.iter().max().unwrap(),
    )
}
