use std::cell::RefCell;
use std::rc::Rc;

use log::{error, info};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{ErrorEvent, MessageEvent, RtcPeerConnection, WebSocket};

use crate::common::{
    handle_message_reply, notify_websocket_connected, notify_websocket_error, AppState,
};

// En lugar de hardcodear, obtener de configuración
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "location"], js_name = hostname)]
    fn hostname() -> String;
}

// Función para obtener la URL del WebSocket según el entorno
fn get_websocket_url() -> String {
    let window = web_sys::window().expect("window should be available");
    let location = window.location();
    let hostname = location.hostname().expect("hostname should be available");

    if hostname.contains("github.io") {
        // Producción en GitHub Pages - conecta a Render
        "wss://webrtc-in-rust.onrender.com".to_string()
    } else if hostname == "localhost" || hostname == "127.0.0.1" {
        // Desarrollo local
        "ws://127.0.0.1:2794".to_string()
    } else {
        // Fallback a producción
        "wss://webrtc-in-rust.onrender.com".to_string()
    }
}

/// Version for React - no DOM manipulation
/// Waits for WebSocket to be fully connected before returning
pub async fn open_web_socket_react(
    rtc_conn: RtcPeerConnection,
    state: Rc<RefCell<AppState>>,
) -> Result<WebSocket, JsValue> {
    let ws_url = "wss://webrtc-in-rust.onrender.com".to_string();
    info!("Connecting to WebSocket: {}", ws_url);

    let ws = WebSocket::new(&ws_url)?;
    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

    let cloned_ws_ext = ws.clone();
    let cloned_state_ext = state;

    // Create a Promise to wait for the WebSocket to open
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let ws_for_callbacks = ws.clone();

        // ON OPEN - Resolve the promise when connection is established
        let resolve_clone = resolve.clone();
        let onopen_callback = Closure::once(move |_event: JsValue| {
            info!("WebSocket connection opened successfully");
            notify_websocket_connected();
            resolve_clone.call0(&JsValue::NULL).unwrap_or_default();
        });
        ws_for_callbacks.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
        onopen_callback.forget();

        // ON ERROR - Reject the promise if connection fails
        let ws_url_clone = ws_url.clone();
        let onerror_callback = Closure::once(move |e: ErrorEvent| {
            error!("WS: onerror_callback error event: {:?}", e);
            let error_msg = format!(
                "Could not make WebSocket connection. Is the signaling server running on: {}?",
                ws_url_clone
            );
            notify_websocket_error(&error_msg);
            reject
                .call1(&JsValue::NULL, &JsValue::from_str(&error_msg))
                .unwrap_or_default();
        });
        ws_for_callbacks.set_onerror(Some(onerror_callback.as_ref().unchecked_ref()));
        onerror_callback.forget();
    });

    // Wait for the WebSocket to open before proceeding
    JsFuture::from(promise).await?;

    // Now set up the message handler (after connection is established)
    let onmessage_callback = Closure::wrap(Box::new(move |ev: MessageEvent| {
        if let Ok(array_buffer) = ev.data().dyn_into::<js_sys::ArrayBuffer>() {
            info!(
                "WS: message event, received arraybuffer: {:?}",
                array_buffer
            );
        } else if let Ok(blob) = ev.data().dyn_into::<web_sys::Blob>() {
            info!("WS: message event, received blob: {:?}", blob);
        } else if let Ok(txt) = ev.data().dyn_into::<js_sys::JsString>() {
            info!("WS: message event, received string: {:?}", txt);
            let rust_string = String::from(txt);
            let rtc_conn_clone = rtc_conn.clone();
            let cloned_ws = cloned_ws_ext.clone();
            let cloned_state = cloned_state_ext.clone();

            wasm_bindgen_futures::spawn_local(async move {
                let result = handle_message_reply(
                    rust_string,
                    rtc_conn_clone.clone(),
                    cloned_ws.clone(),
                    cloned_state,
                )
                .await;
                match result {
                    Err(x) => error!("{:?}", x),
                    _ => {
                        // debug!("Handle Signalling message done")
                    }
                }
            });
        } else {
            info!("message event, received Unknown: {:?}", ev.data());
        }
    }) as Box<dyn FnMut(MessageEvent)>);
    ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
    onmessage_callback.forget();

    Ok(ws)
}

/// Original version with DOM manipulation (kept for backward compatibility)
/// You can remove this once you've fully migrated to React
#[allow(dead_code)]
pub async fn open_web_socket(
    rtc_conn: RtcPeerConnection,
    state: Rc<RefCell<AppState>>,
) -> Result<WebSocket, JsValue> {
    // Call the React version - this removes duplication
    open_web_socket_react(rtc_conn, state).await
}
