# TroubleScope

![](brand/troublescope.png)

TroubleScope is a Falco plugin that exposes Falco proc tree as a FuseFS.  
It can be useful to debug weird proc tree issues.

Also, a `diagnostic` event gets generated every time Falco proc tree diverges from real proc.

The plugin requires the `3.7.0` plugin API version.

## Build

```bash
# Ubuntu
sudo apt install fuse3 libfuse3-dev
git clone --recurse-submodules  git@github.com:FedeDP/troublescope.git
cd troublescope
# Do the following only if you don't have a system-wide vcpkg installation
export VCPKG_ROOT=./vcpkg
cmake -S . -B build --preset linux-gcc
cmake --build build --target troublescope
```

## Formatting

```bash
pre-commit install --install-hooks --hook-type pre-commit --overwrite
# or
pre-commit run --all-files
```

## Run it with Falco (stale do not use it)

- Download falco master tar.gz
- Modify the Falco config

```yaml
load_plugins: [troublescope]

# Customize subsettings for each enabled plugin. These settings will only be
# applied when the corresponding plugin is enabled using the `load_plugins`
# option.
plugins:
  - name: troublescope
    library_path: /home/andrea/personal/troublescope/libtroublescope.so
    init_config: ""
```

```bash
sudo ./usr/bin/falco -c ./etc/falco/falco.yaml -r ./etc/falco/falco_rules.yaml
```

## Run it with sinsp-example

From libs master:

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_DRIVER=ON -DBUILD_BPF=ON -DBUILD_LIBSCAP_MODERN_BPF=ON -DMODERN_BPF_DEBUG_MODE=ON -DUSE_BUNDLED_DEPS=ON -DMINIMAL_BUILD=ON ..
make sinsp-example -j2 
```

Run it:

```bash
sudo /home/andrea/personal/libs/build-sinsp-fast/libsinsp/examples/sinsp-example -p "/home/andrea/personal/troublescope/build/libtroublescope.so|{\"fs_root\": \"/tmp/troublescope\"}" -m -f "evt.type in (open)" 
```
