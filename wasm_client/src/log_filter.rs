//! Logger global filtrado.
//!
//! `wasm_logger` es el único logger del proceso (compartido incluso por los
//! worker threads de rayon vía memoria compartida), así que filtrando aquí
//! silenciamos de golpe todo el ruido INFO de `barnett-smart-card-protocol`,
//! `proof-essentials` y del propio `wasm_client` sin tener que tocar esas
//! crates. Solo dejamos pasar los logs de precompute y de tiempos (más los
//! avisos y errores).

use log::{Level, LevelFilter, Log, Metadata, Record};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn console_log(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = warn)]
    fn console_warn(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn console_error(s: &str);
}

/// Marcadores (en minúsculas) de los únicos logs INFO que queremos ver.
/// El mensaje se compara en minúsculas, así que "Precompute" también encaja.
const KEEP_MARKERS: &[&str] = &["precompute", "[timing]", "[deal]"];

struct FilteredLogger;

impl Log for FilteredLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // Los avisos y errores siempre pasan; los INFO solo si son de
        // precompute o de tiempos.
        let keep = record.level() <= Level::Warn || {
            let msg = record.args().to_string().to_lowercase();
            KEEP_MARKERS.iter().any(|m| msg.contains(m))
        };
        if !keep {
            return;
        }

        let line = format!(
            "{} {}:{} {}",
            record.level(),
            record.file().unwrap_or("?"),
            record.line().unwrap_or(0),
            record.args()
        );
        match record.level() {
            Level::Error => console_error(&line),
            Level::Warn => console_warn(&line),
            _ => console_log(&line),
        }
    }

    fn flush(&self) {}
}

static LOGGER: FilteredLogger = FilteredLogger;

/// Instala el logger filtrado. Idempotente: si ya había uno instalado
/// (p. ej. en un re-init) simplemente no hace nada.
pub fn init() {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(LevelFilter::Info);
}
