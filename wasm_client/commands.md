wasm-pack build --target web --out-dir pkg --release --no-opt
wasm-pack build --target web --out-dir pkg --no-opt

rustup override set nightly

wasm-pack build --out-dir pkg-rayon/ --out-name wasm_client_rayon  --no-opt --target web . 
-Z build-std=panic_abort,std -Z next-lockfile-bump -F rayon


(Get-Content pkg-rayon/package.json) -replace '"name": "([^"]*)"', '"name": "$1-rayon"' | Set-Content pkg-rayon/package.json


wasm-pack build --out-dir pkg-rayon/ --out-name wasm_client_rayon --target web . -Z build-std=panic_abort,std -Z next-lockfile-bump -F rayon


wasm-pack build --out-dir pkg-rayon/ --out-name wasm_client_rayon --target web . -Z build-std=panic_abort,std -Z next-lockfile-bump -F rayon

$env:RUSTFLAGS="-C target-feature=+atomics,+bulk-memory"
$env:RUSTFLAGS='-C target-feature=+atomics,+bulk-memory --cfg getrandom_backend="wasm_js"'


rustup toolchain install nightly-2024-12-20      
>> rustup override set nightly-2024-12-20
rustup toolchain install nightly-2024-12-20      

rustup component add rust-src --toolchain nightly-2024-12-20-x86_64-pc-windows-msvc
       