--[[
 * Automatically generated code. Do not edit.
 * Run genvmi.py to rebuild.
 *
 * Include this file in s2e-config.lua.
 * This include file provides a g_vmi_modules global variable
 * that maps checksums to the module description.
 *
 * s2e-config.lua should have something like this:
 *
 * pluginsConfig.Vmi = {
 *   modules = g_vmi_modules,
 *   ...
 * }
 *
 *
 * The checksum is the one in the PE header.
 * (To be fixed to support other kinds of modules).
]]--

g_vmi_modules = {
    {% for d in data %}
    _{{d.checksum}} = {
      name = "{{d.name}}",
      version = "{{d.version}}",
      checksum = {{d.checksum}},
      nativebase = {{d.nativebase | hex}},
      symbols = {
        {%- for f,a in d.symbols.iteritems() %}

        {{f}} = {{a | hex}},
        {%- endfor %}

      },

      syscalls = {
        {%- for s in d.syscalls %}

        { {{s[0] | hex}}, "{{s[1]}}"},
        {%- endfor %}
      }
    },
    {% endfor %}

}
