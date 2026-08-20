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
- `libutils/` - Utility library (QObject/QAPI, signal/slot, coroutines)
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

## Comments and Documentation
- Write accurate and concise comments. Conciseness does not mean loss of important information and should not make readability worse.
- Comments are accurate first. Verify every claim a comment makes against the code it describes. A comment that promises behavior ("retried later", "cannot happen") must name the mechanism, and the mechanism must exist. Re-derive constants that carry units in their comment (a timeout "in seconds" computed in the wrong unit is a live bug the comment helps find).
- When shortening or rewording a comment, every fact in the old text is either kept or consciously discarded as wrong.
- Do not use "we" in comments. Be specific (e.g., the driver, the caller, etc.).
- Do not overuse semicolons or em-dashes.
- Use doxygen-style comments where appropriate (`///`, `@param`, `@return`). Use proper markers for parameters, etc. Every file starts (after the license header) with a `/// @file` block saying what the module does.
- Comments should be easy to read and sound natural.
- Do not use passive voice when the subject would actually convey additional information.
- In a multi-line comment, do not leave one or two words alone on the last line.
- Do not overuse the word "classic" (e.g., classic cause), "load bearing", "bearing", "seam", "wedged", "latch", "worth stating plainly", "full stop", "carry the argument", "the trap", "isn't just X — it's Y". and other LLMisms.
- Do not use adjectives and other words that bring no value (e.g., honest).
- Minimize jargon and uncommon words. Non-experts should be able to read and understand everything reasonably well.
- When introducing a new term or abbreviation for the first time, define it, especially if it is driver-specific. Common knowledge does not need to be defined (e.g., any standard driver terminology).
- Use plain English in comments and documentation. Do not coin aphorisms or metaphor slogans. A documentation heading must state its point plainly and be understandable before reading the body.
- No punchy fragments for drama. Write complete sentences.
- You are writing technical documentation, not marketing material.
- Some comments are functional and must keep their exact form: formatter on/off markers, and similar tool-consumed comments. Never restyle them.
- Comments justify designs on technical grounds. They do not narrate history, compare against previous implementations, reference external documentation, or paraphrase the code.
- Use American English.
