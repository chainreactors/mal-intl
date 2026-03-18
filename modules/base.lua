
function load_prebuild(arg_1)
    local session = active()
    local arch = barch(session)

    if not arch or arch == "" then
        arch = "x64"
    end

    return load_module(session, arg_1, script_resource("modules/"  .. arg_1 .. "." .. arch .. ".dll"))
end

local load_prebuild_cmd = command("load_prebuild", load_prebuild, "load full|fs|execute|sys|rem precompiled modules", "")
bind_args_completer(load_prebuild_cmd, { values_completer({"full", "fs", "execute", "sys", "rem"}) })

help("load_prebuild", [[
Load precompiled module bundles into the current session.

**Usage (positional argument required):**

```
load_prebuild full
load_prebuild fs
load_prebuild execute
load_prebuild sys
load_prebuild rem
```

> Argument is the module bundle name. Available: full, fs, execute, sys, rem.
]])
