PKG_NAME = wasm_client
WASMPACK_FLAGS = -- --no-opt

.PRECIOUS: pkg-rayon/%.js
pkg-rayon/$(PKG_NAME)-rayon.js rayon:
	RUSTFLAGS='-C target-feature=+atomics,+bulk-memory --cfg getrandom_backend="wasm_js"' rustup run nightly wasm-pack build --out-dir pkg-rayon/ --out-name $(PKG_NAME)_rayon $(WASMPACK_FLAGS) --target web . -Z build-std=panic_abort,std -Z next-lockfile-bump -F rayon
	# Fix package name, append -rayon
	sed -i 's/"name": "\([^"]*\)"/"name": "\1-rayon"/' pkg-rayon/package.json
