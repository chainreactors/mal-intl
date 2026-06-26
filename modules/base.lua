local function prebuild_module_names()
    local modules = {}
    local seen = {}

    for _, filename in ipairs(list_resource("modules")) do
        local name = string.match(filename, "^(.*)%.x64%.dll$")
            or string.match(filename, "^(.*)%.x86%.dll$")
            or string.match(filename, "^(.*)%.dll$")

        if name and not seen[name] then
            seen[name] = true
            table.insert(modules, name)
        end
    end

    table.sort(modules)
    return modules
end

local prebuild_modules = prebuild_module_names()

local function prebuild_help(modules)
    local lines = {
        "Load precompiled module bundles into the current session.",
        "",
        "**Usage (positional argument required):**",
        "",
        "```",
    }

    for _, module in ipairs(modules) do
        table.insert(lines, "load_prebuild " .. module)
    end

    table.insert(lines, "```")
    table.insert(lines, "")
    table.insert(lines, "> Argument is the module bundle name. Available: " .. table.concat(modules, ", ") .. ".")

    return table.concat(lines, "\n")
end

function load_prebuild(arg_1)
    local session = active()
    local arch = barch(session)

    if not arch or arch == "" then
        arch = "x64"
    end

    return load_module(session, arg_1, script_resource("modules/"  .. arg_1 .. "." .. arch .. ".dll"))
end

local load_prebuild_cmd = command("load_prebuild", load_prebuild, "load " .. table.concat(prebuild_modules, "|") .. " precompiled modules", "")
bind_args_completer(load_prebuild_cmd, { values_completer(prebuild_modules) })

help("load_prebuild", prebuild_help(prebuild_modules))
