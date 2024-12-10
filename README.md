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
make all
```

## Formatting

```bash
pre-commit install --install-hooks --hook-type pre-commit --overwrite
# or
pre-commit run --all-files
```
