local SCRIPTS_BASE_URL = "YOUR_SCRIPTS_BASE_URL_HERE"
local PLACE_MAP = {
    [2788229376]          = "DaHood.lua",
    [142823291]           = "Mm2.lua",
    [128736949265057]     = "Gakuran.lua",
    [83038462357724]      = "GrabenUndReinigen.lua",
    [94640181989498]      = "GrowAChickenFighter.lua",
    [107778070777162]     = "StealAnEgg.lua",
    [126870639873289]     = "JumpForPets.lua",
    [100068273119174]     = "LeafSimulator.lua",
    [108628039999641]     = "NeedleHaystack.lua",
    [77108422251420]      = "NeedleHaystack.lua",
    [17625359962]         = "Rivals.lua",
    [106484206883664]     = "DungeonLootr.lua",
}
local GAME_MAP = {
    [9656201728]          = "DungeonLootr.lua",
    [10690360998]         = "JumpForPets.lua",
    [10756011174]         = "NeedleHaystack.lua",
    [6035872082]          = "Rivals.lua",
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
