# troublescope

This is a Falco plugin that exposes Falco proc tree as a FuseFS.  
It can be useful to debug weird proc tree issues.

Also, a `diagnostic` event gets generated every time Falco proc tree diverges from real proc.

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

## Run it

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
