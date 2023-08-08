use gloo_timers::callback::Interval;
use leptos::leptos_dom::ev::{SubmitEvent};
use leptos::*;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::to_value;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "tauri"])]
    async fn invoke(cmd: &str, args: JsValue) -> JsValue;
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "tauri"])]
    async fn invoke_arg0(cmd: &str) -> JsValue;
}

#[derive(Serialize, Deserialize)]
struct GreetArgs<'a> {
    name: &'a str,
}

#[component]
pub fn Flows(cx: Scope) -> impl IntoView {
    let (flows, set_flows) = create_signal(cx, Vec::<String>::new());
    Interval::new(1_000, move || {
        spawn_local(async move {

            // Grab a new set of flows
            let new_msg = invoke_arg0("dump_connection_keys").await;
            set_flows.set(vec!["hi".to_string()]);
        });

    });
    view!{ cx,
        <table>
            <thead>
            <th> Flow ID </th>
            <th> Flow Key </th>
            </thead>
            <For
                each=move || flows.get()
                key=|flow| flow.clone() // each flow is itself a unique ID
                view=move |cx, flow: String| {
                    view!{cx,

                    }
                }
            />
        </table>
    }
}

#[component]
pub fn Hello(cx: Scope) -> impl IntoView {
    let (name, set_name) = create_signal(cx, String::new());
    let (greet_msg, set_greet_msg) = create_signal(cx, String::new());

    let update_name = move |ev| {
        let v = event_target_value(&ev);
        set_name.set(v);
    };

    let greet = move |ev: SubmitEvent| {
        ev.prevent_default();
        spawn_local(async move {
            if name.get().is_empty() {
                return;
            }

            let args = to_value(&GreetArgs { name: &name.get() }).unwrap();
            // Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
            let new_msg = invoke("greet", args).await.as_string().unwrap();
            set_greet_msg.set(new_msg);
        });
    };

    view! { cx,
        <main class="container">
            <form class="row" on:submit=greet>
                <input
                    id="greet-input"
                    placeholder="Enter a name..."
                    on:input=update_name
                />
                <button type="submit">"Greet"</button>
            </form>
            <p><b>{ move || greet_msg.get() }</b></p>
        </main>
    }
}