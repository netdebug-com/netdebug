# Rust code coverage 

The `cargo-llvm-cov` package does most of the heavy lifting. See https://github.com/taiki-e/cargo-llvm-cov

##  Run and generate HTML output: 
  ```
  cargo llvm-cov test --html
  ls llvm-cov/html/index.html
  # on MacOS you can just run 
  open llvm-cov/html/index.html
  ```

## Nicer HTML output

The HTML that it produces is a bit hard to read/understand. You can get a better one by generating `lcov` output and then using lcov's `genhtml` command to get a nicer HTML. 

* Install `lcov` tools. On Mac: `brew install lcov`
* Generate lcov output and then generate html
  ```
  mkdir tmp-coverage
  cargo llvm-cov test --lcov --output-path tmp-coverage/x.lcov 
  genhtml -o tmp-coverage/ tmp-coverage/x.lcov
  open tmp-coverage/index.html
  ```


