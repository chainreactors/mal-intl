local prebuild_modules = {}
local seen_prebuild_modules = {}

for _, filename in ipairs(list_resource("modules")) do
    local module = filename:sub(1, filename:find(".", 1, true) - 1)
    if not seen_prebuild_modules[module] then
        seen_prebuild_modules[module] = true
        prebuild_modules[#prebuild_modules + 1] = module
    end
end

table.sort(prebuild_modules)

local prebuild_examples = {}
for _, module in ipairs(prebuild_modules) do
    prebuild_examples[#prebuild_examples + 1] = "load_prebuild " .. module
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

help("load_prebuild", table.concat({
    "Load precompiled module bundles into the current session.",
    "",
    "**Usage (positional argument required):**",
    "",
    "```",
    table.concat(prebuild_examples, "\n"),
    "```",
    "",
    "> Argument is the module bundle name. Available: " .. table.concat(prebuild_modules, ", ") .. ".",
}, "\n"))
