local SCRIPTS_BASE_URL = "https://raw.githubusercontent.com/idrisvale-dev/NH/refs/heads/master/Scripts/""
local PLACE_MAP = {
    [2788229376]          = "DaHood.luau",
    [142823291]           = "Mm2.luau",
    [128736949265057]     = "Gakuran.luau",
    [83038462357724]      = "GrabenUndReinigen.luau",
    [94640181989498]      = "GrowAChickenFighter.luau",
    [107778070777162]     = "StealAnEgg.luau",
    [126870639873289]     = "JumpForPets.luau",
    [100068273119174]     = "LeafSimulator.luau",
    [108628039999641]     = "NeedleHaystack.luau",
    [77108422251420]      = "NeedleHaystack.luau",
    [17625359962]         = "Rivals.luau",
    [106484206883664]     = "DungeonLootr.luau",
}
local GAME_MAP = {
    [9656201728]          = "DungeonLootr.luau",
    [10690360998]         = "JumpForPets.luau",
    [10756011174]         = "NeedleHaystack.luau",
    [6035872082]          = "Rivals.luau",
}
local function resolveScript()
    local pid = game.PlaceId
    if PLACE_MAP[pid] then return PLACE_MAP[pid] end
    local gid = game.GameId
    if GAME_MAP[gid] then return GAME_MAP[gid] end
    return "Universal.lua"
end
local function run()
    local script_name = resolveScript()
    local url = SCRIPTS_BASE_URL .. script_name
    local ok, source = pcall(function()
        return game:HttpGet(url, true)
    end)
    if not ok or not source or source == "" then
        warn("[NevaHubLoader] Failed to fetch: " .. url)
        if script_name ~= "Universal.lua" then
            pcall(function()
                local fallback = game:HttpGet(SCRIPTS_BASE_URL .. "Universal.lua", true)
                loadstring(fallback)()
            end)
        end
        return
    end
    local fn, err = loadstring(source)
    if not fn then
        warn("[NevaHubLoader] Parse error in " .. script_name .. ": " .. tostring(err))
        return
    end
    local runOk, runErr = pcall(fn)
    if not runOk then
        warn("[NevaHubLoader] Runtime error in " .. script_name .. ": " .. tostring(runErr))
    end
end
run()
