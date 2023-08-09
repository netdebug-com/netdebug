use std::{collections::HashMap, sync::Arc};

use wasm_bindgen::JsValue;

use crate::{console_log, log, html};

pub type TabId = String;
pub type Tabs = Arc<TabsContext>;

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

    pub(crate) fn construct(&self) -> Result<(), JsValue> {
        let root_div = html!("div", {
            "name" => "tabs_div",
            "id" => "container",
        })?;
        let ul = html!("ul", {
            "class" => "tabs",
        })?;
        root_div.append_child(&ul)?;
        for tab_id in &self.tab_order {
            let tab = self.tabs.get(tab_id).expect("missing tab!?");
            let li = html!("li", {
                "class" => "tabs__label",
                // TODO: add 'onClick' property
            })?;
            li.set_inner_html(&tab.text);
            ul.append_child(&li)?;
        }

        let active_tab = self.tabs.get(&self.active_tab).expect("no active tab!?");
        if let Some(closure) = &active_tab.on_activate {
            console_log!("Activating tab {}", active_tab.name);
            closure(active_tab);
        }

        let body = web_sys::window()
            .expect("window")
            .document()
            .expect("document")
            .body()
            .expect("body");
        body.append_child(&root_div)?;

        Ok(())
    }
}

pub struct Tab {
    // the element.id of the tab
    pub name: TabId,
    // the html text of the tab
    pub text: String,
    // closure to call on clicking the tab
    pub on_activate: Option<fn(&Tab)>,
    // closure to call on clicking another tab
    pub on_deactivate: Option<fn(&Tab)>,
}
