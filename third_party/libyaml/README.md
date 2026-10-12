# libyaml

The `include/` and `src/` files of [libyaml](https://github.com/yaml/libyaml) release 0.2.5 (tag
`0.2.5`, commit `2c891fc7a770e8ba2fec34fc6b545c672beb37e6`), unmodified. gwlbtun uses its parser and
document loader to read configuration files (`-f`); `GwlbtunConfig.cpp` is the only user.

CMakeLists.txt compiles these sources into gwlbtun with `YAML_DECLARE_STATIC` and the version macros
that libyaml's own build would put in `config.h`, optimised for size, and the linker drops the parts
gwlbtun doesn't use (mostly the emitter).

libyaml is MIT licensed; see `License`.
