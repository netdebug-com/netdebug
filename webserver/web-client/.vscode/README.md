

# tell VScode that for this directory, look at the code as if the build target is wasm32
# this helps us use the IDE the way it was intended even though we're technically cross compiling
    "rust-analyzer.cargo.target": "wasm32-unknown-unknown"
