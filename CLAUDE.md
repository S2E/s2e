# CLAUDE.md - S2E Project Guidelines

## Project Overview

S2E is a symbolic execution platform. This repository builds `libs2e.so`, a shared library preloaded into QEMU to enable symbolic execution. Documentation: https://s2e.systems/docs

## Repository Structure

- `libs2e/` - Core KVM interface library (preloaded into QEMU)
- `libs2ecore/` - S2E core engine
- `libs2eplugins/` - S2E analysis plugins
- `libcpu/` - CPU emulation library
- `libtcg/` - TCG (Tiny Code Generator) library
- `klee/` - KLEE symbolic execution engine (fork)
- `libvmi/` - Virtual machine introspection
- `libq/` - Utility library
- `libfsigc++/` - Signal/slot library
- `libcoroutine/` - Coroutine support
- `guest/` - Guest-side tools and libraries
- `tools/` - Offline analysis tools
- `lua/` - Lua headers (for plugin configuration)

## Build System

- Use the existing S2E environment for building. Its base path is typically ~/s2e/env.
- cd ~/s2e/env/build/libs2e-release && make

## General Code Style
- Use C++20 in all components.
- **Header guards**: `#ifndef S2E_*_H` / `#define` / `#endif`
- Use `///` for license headers
- Use braces for all if/for/while, etc. blocks, even when there is only a single instructions.
- **Member variables**:
   - `m_` prefix + `snake_case` (e.g., `m_devices`)
   - Class member variables should go at the beginning of the class.
- **Namespaces**: lowercase (e.g., `s2e::kvm`)
- **Class names**: `PascalCase` (e.g., `VirtualDeviceManager`)

## Code Style for `libs2e/*`
- **Method/function names**: `snake_case` (e.g., `mmio_read`, `find_device`)


## Commit Messages

Follow the existing convention: `component: short description` in lowercase.
Examples:
- `libs2e: implemented basic device manager`
- `libcpu: removed unused ymm fields`
- `libs2ecore: allow any sizes for read/writes from/to concrete regions`
