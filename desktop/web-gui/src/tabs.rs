use std::{any::Any, collections::HashMap, sync::Arc};

use wasm_bindgen::{prelude::Closure, JsCast, JsValue};
use web_sys::{HtmlElement, MessageEvent, WebSocket};

use crate::{console_log, html, log};

pub type TabId = String;
pub type Tabs = Arc<std::sync::Mutex<TabsContext>>;

pub struct TabsContext {
    tabs: HashMap<String, Tab>,
    tab_order: Vec<TabId>,
    active_tab: TabId,
}

impl TabsContext {
    pub(crate) fn new(in_tabs: Vec<Tab>, active_tab: TabId) -> TabsContext {
        let mut tabs = HashMap::new();
        let tab_order = in_tabs.iter().map(|t| t.name.clone()).collect();
        for t in in_tabs {
            tabs.insert(t.name.clone(), t);
        }
        // raise an assertion if the named active tab is not an existing tab
        assert!(tabs.contains_key(&active_tab));
        TabsContext {
            tabs,
            tab_order,
            active_tab,
        }
    }

    pub fn get_active_tab_name(&self) -> TabId {
        self.active_tab.clone()
    }

    pub fn get_active_tab(&mut self) -> Option<&mut Tab> {
        self.tabs.get_mut(&self.active_tab)
    }

    /**
     * Build the tabs for the first time.
     *
     * This is a bit funky as we have two copies of the tabs structure,
     * one without the Arc() in self and one with the Arc() in tabs_clone.
     * This is because we need to pass a reference to ourselves into the closure
     * which we can't do from self.
     */

    pub(crate) fn construct(&mut self, tabs_clone: Tabs, ws: WebSocket) -> Result<(), JsValue> {
        let root_div = html!("div", {
            "name" => "tab",
        })?;
        for tab_id in &self.tab_order {
            let tabs = tabs_clone.clone();
            let tab_id_clone = tab_id.clone();
            let ws_clone = ws.clone();
            let on_click = Closure::<dyn FnMut(_)>::new(move |_e: MessageEvent| {
                // all of these clone()'s are so that we can call this function many times
                // instead of just once, e.g., so it's a FnMut rather than a FnOnce
                let mut tabs_lock = tabs.lock().unwrap();
                if let Err(e) = tabs_lock.activate(tab_id_clone.clone(), ws_clone.clone()) {
                    console_log!("Error: {:?}", e.as_string());
                }
            });
            let tab = self.tabs.get(tab_id).expect("missing tab!?");
            let button = html!("button", {
                "class" => "tablinks",
                "id" => TabsContext::tab_id_to_dom_id(&tab.name).as_str(),
            })?
            .dyn_into::<HtmlElement>()
            .unwrap();
            button.set_inner_html(&tab.text);
            button.set_onclick(Some(on_click.as_ref().unchecked_ref()));
            on_click.forget();
            root_div.append_child(&button)?;
        }

        let body = web_sys::window()
            .expect("window")
            .document()
            .expect("document")
            .body()
            .expect("body");
        body.append_child(&root_div)?;
        let container = html!("div", {"id" => "tab_content", "class" => "tabs_content"})?;
        body.append_child(&container)?;
        // do this after we've added everything to the DOM
        let active_tab = self
            .tabs
            .get_mut(&self.active_tab)
            .expect("no active tab!?");
        // need to manually call this here rather than call the activate() function
        // as there is no old tab to deactivate
        if let Some(activate_fn) = &active_tab.on_activate {
            console_log!("Activating tab {}", active_tab.name);
            activate_fn(active_tab, ws);
        }

        let document = web_sys::window()
            .expect("window")
            .document()
            .expect("document");
        let button = document
            .get_element_by_id(&TabsContext::tab_id_to_dom_id(&active_tab.name))
            .unwrap();
        button.set_attribute("checked", "true")?;

        Ok(())
    }

    /**
     * Deactivate the old tab and activate the new one
     */
    fn activate(&mut self, tab: TabId, ws: WebSocket) -> Result<(), JsValue> {
        console_log!("Setting tab to {}", &tab);
        let document = web_sys::window()
            .expect("window")
            .document()
            .expect("document");
        if let Some(old_tab) = self.tabs.get_mut(&self.active_tab) {
            if let Some(deactivate_fn) = old_tab.on_deactivate {
                deactivate_fn(old_tab, ws.clone());
            }
            let button = document
                .get_element_by_id(&TabsContext::tab_id_to_dom_id(&old_tab.name))
                .unwrap();
            button.set_attribute("checked", "false")?;
        } else {
            // old_tab does not exit?  probaly warn, but just ignore for now
        }
        if let Some(new_tab) = self.tabs.get_mut(&tab) {
            if let Some(activate_fn) = new_tab.on_activate {
                activate_fn(new_tab, ws);
            }
            let button = document
                .get_element_by_id(&TabsContext::tab_id_to_dom_id(&new_tab.name))
                .unwrap();
            button.set_attribute("checked", "true")?;
        } else {
            return Err(JsValue::from_str(
                format!("tab {} not in tabs list", tab).as_str(),
            ));
        }
        self.active_tab = tab;
        Ok(())
    }

    fn tab_id_to_dom_id(tab_id: &str) -> String {
        format!("__tab_id_{}", tab_id)
    }
}

pub struct Tab {
    // the element.id of the tab
    pub name: TabId,
    // the html text of the tab
    pub text: String,
    // closure to call on clicking the tab
    pub on_activate: Option<fn(&mut Tab, WebSocket)>,
    // closure to call on clicking another tab
    pub on_deactivate: Option<fn(&mut Tab, WebSocket)>,
    // place for private data for the tab
    pub data: Option<Box<dyn Any>>,
}
