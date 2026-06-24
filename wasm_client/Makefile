PKG_NAME = wasm_client

# RUSTFLAGS para el build multihilo (wasm-bindgen-rayon).
# IMPRESCINDIBLE en este nightly (1.97): NO activa memoria compartida solo con
# `atomics`, hay que forzar a wasm-ld:
#   - +mutable-globals           -> globals TLS mutables (base de cada hilo)
#   - --shared-memory            -> memoria SharedArrayBuffer (si no, postMessage(memory) revienta)
#   - --import-memory            -> wasm-bindgen exige memoria importada para threads (assert mem.import.is_some())
#   - --max-memory=1GiB          -> shared memory requiere maximo. OJO: para memoria
#       COMPARTIDA el navegador reserva el `maximum` ENTERO de golpe al crearla.
#       4GiB falla al asignar -> initThreadPool revienta -> 1 hilo (~44s). 1GiB va.
#   - --export-if-defined=__wasm_init_tls (+ __tls_*) -> wasm-bindgen llama a estos por hilo
# Sin esto: initThreadPool peta, prove cae a 1 hilo (~55s en vez de ~5s).
RAYON_RUSTFLAGS = -C target-feature=+atomics,+bulk-memory,+mutable-globals --cfg getrandom_backend="wasm_js" -C link-arg=--shared-memory -C link-arg=--import-memory -C link-arg=--max-memory=1073741824 -C link-arg=--export-if-defined=__wasm_init_tls -C link-arg=--export-if-defined=__tls_size -C link-arg=--export-if-defined=__tls_base -C link-arg=--export-if-defined=__tls_align

.PRECIOUS: pkg-rayon/%.js
pkg-rayon/$(PKG_NAME)-rayon.js rayon:
	RUSTFLAGS='$(RAYON_RUSTFLAGS)' rustup run nightly wasm-pack build --target web --out-dir pkg-rayon/ --out-name $(PKG_NAME)_rayon --no-opt . -- -Z build-std=panic_abort,std -Z next-lockfile-bump --features rayon
	# Fix package name, append -rayon
	sed -i 's/"name": "\([^"]*\)"/"name": "\1-rayon"/' pkg-rayon/package.json

# OPTIMIZACION DEL WASM (paso MANUAL imprescindible tras `make rayon`).
#
# El build usa `--no-opt` porque el `wasm-opt` por defecto NO conoce los flags de
# threads y rompe la memoria compartida/atomics. Hay que correr `wasm-opt` a mano
# pasandole los flags de threads. SIN este paso el prove va ~2,5x mas lento
# (medido: v100 sin optimizar prove ~16 s; optimizado ~5,6 s warm). El tamano del
# .wasm apenas baja (~103->101 MB) pero la velocidad del prove cae a la mitad.
#
# `wasm-opt` viene en la cache de wasm-pack:
#   ~/AppData/Local/.wasm-pack/wasm-opt-*/bin/wasm-opt.exe  (Windows)
#   ~/.cache/.wasm-pack/wasm-opt-*/bin/wasm-opt             (Linux/Mac)
WASM_OPT = $(firstword $(wildcard $(HOME)/AppData/Local/.wasm-pack/wasm-opt-*/bin/wasm-opt.exe $(HOME)/.cache/.wasm-pack/wasm-opt-*/bin/wasm-opt) wasm-opt)
RAYON_WASM = pkg-rayon/$(PKG_NAME)_rayon_bg.wasm

optimize-rayon:
	cp $(RAYON_WASM) $(RAYON_WASM).noopt
	"$(WASM_OPT)" -O2 --enable-threads --enable-bulk-memory --enable-mutable-globals --enable-sign-ext $(RAYON_WASM).noopt -o $(RAYON_WASM)
	@echo "optimize-rayon OK -> copia pkg-rayon/* a frontend-production/public/pkg-rayon/"
