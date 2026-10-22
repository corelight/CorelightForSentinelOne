-- OCSF Corelight serializer.

-- =========================================================
-- CONSTANTS
-- =========================================================

local PRODUCT_NAME = "Corelight"
local VENDOR_NAME  = "Corelight"
local OCSF_VERSION = "1.8.0"

local IGNORE_FIELDS = {
    _corelight_event_type = true,
    _corelight_query_time = true,
    _ob                   = true,
}

-- =========================================================
-- HELPERS
-- =========================================================

local MONTH_ABBR = {
    JAN = 1, FEB = 2, MAR = 3, APR = 4, MAY = 5,  JUN = 6,
    JUL = 7, AUG = 8, SEP = 9, OCT = 10, NOV = 11, DEC = 12,
}

local function convertToMilliseconds(ts)
    -- Epoch time (Zeek's default JSON ts), as a number or a numeric string:
    -- values above 1e11 are already milliseconds, smaller ones are seconds.
    local epoch = tonumber(ts)
    if epoch ~= nil and (type(ts) == "number" or ts:match("^%s*%d+%.?%d*%s*$")) then
        if epoch > 1e11 then return math.floor(epoch) end
        return math.floor(epoch * 1000)
    end
    if type(ts) ~= "string" or ts == "" then return nil end
    local year, month, day, hour, minute, second =
        ts:match("^(%d%d%d%d)-(%d%d)-(%d%d)[T ](%d%d):(%d%d):(%d%d)")
    if not year then
        local first, sec_field, sl_year, sl_hour, sl_minute, sl_second =
            ts:match("^(%d%d?)/(%d%d?)/(%d%d%d%d)[:%s](%d%d):(%d%d):(%d%d)")
        if first then
            year, hour, minute, second = sl_year, sl_hour, sl_minute, sl_second
            if tonumber(first) > 12 then
                day, month = first, sec_field
            else
                month, day = first, sec_field
            end
        end
    end
    if not year then
        local mon_name, mn_day, mn_hour, mn_minute, mn_second =
            ts:match("^(%a%a%a)%s+(%d%d?)%s+(%d%d):(%d%d):(%d%d)")
        if mon_name then
            month = MONTH_ABBR[mon_name:upper()]
            if month then
                day, hour, minute, second = mn_day, mn_hour, mn_minute, mn_second
                local now = os.date("*t", os.time())
                year = now.year
                if month > now.month + 1 then year = year - 1 end
            end
        end
    end
    if not year then return nil end
    year, month, day, hour, minute, second =
        tonumber(year), tonumber(month), tonumber(day),
        tonumber(hour), tonumber(minute), tonumber(second)
    local frac_ms = 0
    local frac = ts:match("^%d%d%d%d%-%d%d%-%d%d[T ]%d%d:%d%d:%d%d%.(%d+)")
    if frac then
        frac_ms = tonumber((frac .. "000"):sub(1, 3)) or 0
    end
    local tz_str = ts:match("[T ]%d%d:%d%d:%d%d[%.%d]*(.-)%s*$") or "Z"
    if tz_str == "" then tz_str = "Z" end
    local tz_offset = 0
    if tz_str ~= "Z" then
        local sign, tz_hours, tz_minutes = tz_str:match("^([%+%-])(%d%d):?(%d%d)$")
        if sign then
            tz_offset = tonumber(tz_hours) * 3600 + tonumber(tz_minutes) * 60
            if sign == "-" then tz_offset = -tz_offset end
        end
    end
    local month_adjust  = math.floor((14 - month) / 12)
    local julian_year   = year + 4800 - month_adjust
    local julian_month  = month + 12 * month_adjust - 3
    local julian_day    = day
              + math.floor((153 * julian_month + 2) / 5)
              + 365 * julian_year
              + math.floor(julian_year / 4)
              - math.floor(julian_year / 100)
              + math.floor(julian_year / 400)
              - 32045
    local epoch_s = (julian_day - 2440588) * 86400 + hour * 3600 + minute * 60 + second - tz_offset
    return math.floor(epoch_s * 1000 + frac_ms)
end

local function splitPath(path)
    local segs, cur, i = {}, "", 1
    while i <= #path do
        local c = path:sub(i, i)
        if c == "\\" and i < #path then
            cur = cur .. path:sub(i + 1, i + 1)
            i = i + 2
        elseif c == "." then
            segs[#segs + 1] = cur
            cur = ""
            i = i + 1
        else
            cur = cur .. c
            i = i + 1
        end
    end
    segs[#segs + 1] = cur
    return segs
end

local function getNestedField(obj, path)
    if obj == nil or path == nil or path == "" then return nil end
    -- Fast-path: try the whole path as a literal flat key first.
    -- Corelight/Zeek events carry fields like "id.orig_h" as literal string
    -- keys (not nested tables), so this must be attempted before dot-splitting.
    if type(obj) == "table" and obj[path] ~= nil then return obj[path] end
    local cursor = obj
    for _, key in ipairs(splitPath(path)) do
        if type(cursor) ~= "table" then return nil end
        local name, idx = key:match("^(.+)%[(%d+)%]$")
        if name then
            cursor = cursor[name]
            if type(cursor) ~= "table" then return nil end
            cursor = cursor[tonumber(idx) + 1]
        else
            cursor = cursor[key]
        end
        if cursor == nil then return nil end
    end
    return cursor
end

local function setNestedField(obj, path, value)
    if obj == nil or value == nil or value == "" or path == nil or path == "" then return end
    if type(obj) ~= "table" then return end
    local keys = {}
    for key in string.gmatch(path, "[^.]+") do table.insert(keys, key) end
    if #keys == 0 then return end
    local cursor = obj
    for i = 1, #keys - 1 do
        local k = keys[i]
        local name, idx = k:match("^(.+)%[(%d+)%]$")
        if name then
            local n = tonumber(idx) + 1
            if cursor[name] == nil then cursor[name] = {} end
            if cursor[name][n] == nil then cursor[name][n] = {} end
            cursor = cursor[name][n]
        else
            if cursor[k] == nil then cursor[k] = {} end
            cursor = cursor[k]
        end
    end
    local k = keys[#keys]
    local name, idx = k:match("^(.+)%[(%d+)%]$")
    if name then
        local n = tonumber(idx) + 1
        if cursor[name] == nil then cursor[name] = {} end
        cursor[name][n] = value
    else
        cursor[k] = value
    end
end

local function getValue(tbl, key, default)
    if tbl == nil then return default end
    local v = getNestedField(tbl, key)
    if v == nil then return default end
    return v
end

local function no_nulls(d)
    if type(d) == "table" then
        for k, v in pairs(d) do
            if type(v) == "userdata" then d[k] = nil
            elseif type(v) == "table" then no_nulls(v) end
        end
    end
    return d
end

local function pruneScoped(t, node)
    if type(t) ~= "table" or type(node) ~= "table" then return end
    for k, child in pairs(node) do
        if k ~= "_leaf" and k ~= "_idx" and type(child) == "table" then
            if child._leaf then
                t[k] = nil
            elseif type(t[k]) == "table" then
                pruneScoped(t[k], child)
                if next(t[k]) == nil then t[k] = nil end
            end
        end
    end
end

local function walk(src, dst, node)
    if type(src) ~= "table" then return end
    for k, v in pairs(src) do
        local child = node[k]
        if child == nil then
            -- Not in the mapped-keys trie: copy to unmapped.
            if v ~= "" then dst[k] = v end
        elseif not child._leaf then
            -- Non-leaf trie node: a descendant of this key is mapped.
            -- Recurse into table values; pass through scalars (their path is
            -- partially mapped but this exact key is not).
            if type(v) == "table" then
                if #v > 0 then
                    local arr = {}
                    for elem_i, elem in ipairs(v) do
                        if type(elem) == "table" then
                            local elem_dst = {}
                            walk(elem, elem_dst, child)
                            if child._idx and child._idx[elem_i] then
                                pruneScoped(elem_dst, child._idx[elem_i])
                            end
                            if next(elem_dst) ~= nil then
                                arr[#arr + 1] = elem_dst
                            end
                        elseif elem ~= "" then
                            arr[#arr + 1] = elem
                        end
                    end
                    if #arr > 0 then dst[k] = arr end
                else
                    dst[k] = dst[k] or {}
                    walk(v, dst[k], child)
                    if next(dst[k]) == nil then dst[k] = nil end
                end
            elseif v ~= "" then
                dst[k] = v
            end
        end
        -- child._leaf=true: this key is directly mapped; exclude from unmapped.
    end
end

local function copyField(source, target, sourcePath, targetPath)
    if source == nil or target == nil or sourcePath == nil or targetPath == nil then return false end
    local value = getNestedField(source, sourcePath)
    if value == nil or value == "" then return false end
    setNestedField(target, targetPath, value)
    return true
end

-- Some source fields (e.g. Zeek's "service") may be a string or an array;
-- when an array, the first element is the value of interest.
local function firstScalar(val)
    if type(val) == "table" then return val[1] end
    return val
end

local function copyUnmappedFields(event, result, mapped_keys)
    result.unmapped = result.unmapped or {}
    local trie = {}
    for path, _ in pairs(mapped_keys) do
        -- Also register the whole path as a literal flat key in the trie so
        -- that Corelight/Zeek-style "id.orig_h" keys (flat string keys with
        -- dots) are excluded from unmapped even though they are not nested.
        if path:find(".", 1, true) then
            if not trie[path] then trie[path] = {} end
            trie[path]._leaf = true
        end
        local node = trie
        for _, seg in ipairs(splitPath(path)) do
            local name, idx = seg:match("^(.+)%[(%d+)%]$")
            if name then
                if not node[name] then node[name] = {} end
                node = node[name]
                node._idx = node._idx or {}
                local n = tonumber(idx) + 1
                node._idx[n] = node._idx[n] or {}
                node = node._idx[n]
            else
                name = seg:match("^(.+)%[%]$") or seg
                if not node[name] then node[name] = {} end
                node = node[name]
            end
        end
        node._leaf = true
    end
    local filtered_event = {}
    for k, v in pairs(event) do
        if not IGNORE_FIELDS[k] then filtered_event[k] = v end
    end
    walk(filtered_event, result.unmapped, trie)
    if next(result.unmapped) == nil then result.unmapped = nil end
end

-- Returns a copy of the event without fields whose value is 0 (nested
-- objects are filtered recursively, arrays are kept as-is). Used by the
-- corelight_metrics_bro and corelight_metrics_disk handlers, where most fields
-- are zero counters: dropping them keeps metrics_bro under SDL's
-- 100,000-character event limit, and a missing counter there means 0.
local function withoutZeroCounters(t)
    local out = {}
    for k, v in pairs(t) do
        if type(v) == "table" and #v == 0 and next(v) ~= nil then
            local sub = withoutZeroCounters(v)
            if next(sub) ~= nil then out[k] = sub end
        elseif v ~= 0 then
            out[k] = v
        end
    end
    return out
end

local function addObservables(observables, name, typ, tid, val)
    if type(val) == "table" then
        for _, item in ipairs(val) do
            if item ~= nil and item ~= "" then
                table.insert(observables,
                    { name = name, type = typ, type_id = tid, value = tostring(item) })
            end
        end
        return
    end
    if val ~= nil and val ~= "" then
        table.insert(observables,
            { name = name, type = typ, type_id = tid, value = tostring(val) })
    end
end

-- True for internal addresses: IPv4 RFC1918 (10/8, 172.16/12, 192.168/16),
-- RFC6598 (100.64/10), loopback (127/8) and link-local (169.254/16); IPv6
-- ULA (fc00::/7), link-local (fe80::/10) and loopback (::1).
local function isPrivateIP(ip)
    if type(ip) ~= "string" or ip == "" then return false end
    -- IPv4-mapped IPv6 (::ffff:a.b.c.d) is classified by its IPv4 part
    local mapped = ip:lower():match("^::ffff:(%d+%.%d+%.%d+%.%d+)$")
    if mapped then ip = mapped end
    if ip:find(":", 1, true) then
        local v6 = ip:lower()
        return v6 == "::1" or v6:match("^f[cd]%x%x:") ~= nil or v6:match("^fe[89ab]%x:") ~= nil
    end
    local a, b = ip:match("^(%d+)%.(%d+)%.")
    if not a then return false end
    a, b = tonumber(a), tonumber(b)
    if a == 10 or a == 127 then return true end
    if a == 172 and b >= 16 and b <= 31 then return true end
    if a == 192 and b == 168 then return true end
    if a == 100 and b >= 64 and b <= 127 then return true end
    if a == 169 and b == 254 then return true end
    return false
end

-- True for multicast (224.0.0.0/4, ff00::/8) and limited broadcast
-- (255.255.255.255). Such traffic is neither inbound nor outbound, so
-- computeDirection reports it as Unknown.
local function isMulticastOrBroadcast(ip)
    if type(ip) ~= "string" then return false end
    ip = ip:lower():match("^::ffff:(%d+%.%d+%.%d+%.%d+)$") or ip
    if ip == "255.255.255.255" then return true end
    if ip:lower():match("^ff%x%x:") then return true end
    local a = tonumber(ip:match("^(%d+)%."))
    return a ~= nil and a >= 224 and a <= 239
end

local function computeDirection(src_ip, dst_ip)
    local src_priv = isPrivateIP(src_ip)
    local dst_priv = isPrivateIP(dst_ip)
    if src_ip == nil or src_ip == "" or dst_ip == nil or dst_ip == "" then
        return 0, "Unknown"
    end
    if isMulticastOrBroadcast(dst_ip) then return 0, "Unknown" end
    if src_priv and not dst_priv then return 2, "Outbound" end
    if src_priv and dst_priv then return 3, "Lateral" end
    if not src_priv and dst_priv then return 1, "Inbound" end
    return 0, "Unknown"
end

-- Direction from the sensor's own local_orig/local_resp flags (set from its
-- local_nets configuration). Returns nil when the log does not carry both
-- flags, so the caller can fall back to computeDirection.
local function localNetsDirection(event)
    local lo = getValue(event, "local_orig")
    local lr = getValue(event, "local_resp")
    if lo == nil or lr == nil then return nil end
    lo = (lo == true or lo == "true")
    lr = (lr == true or lr == "true")
    if lo and lr then return 3, "Lateral" end
    if lo then return 2, "Outbound" end
    if lr then return 1, "Inbound" end
    return 0, "Unknown"
end

local function isPlaceholder(s)
    if s == nil then return true end
    if type(s) ~= "string" then return false end
    local t = s:match("^%s*(.-)%s*$")
    return t == "" or t == "-" or t:lower() == "null" or t:lower() == "none" or t:lower() == "unknown"
end

local function jsonEscape(s)
    return (s:gsub('[%c"\\]', function(c)
        if c == '"' then return '\\"'
        elseif c == '\\' then return '\\\\'
        elseif c == '\n' then return '\\n'
        elseif c == '\r' then return '\\r'
        elseif c == '\t' then return '\\t'
        else return string.format('\\u%04x', c:byte())
        end
    end))
end

local function jsonEncode(val)
    local t = type(val)
    if t == "string" then
        return '"' .. jsonEscape(val) .. '"'
    elseif t == "boolean" then
        return tostring(val)
    elseif t == "number" then
        -- NaN / +-inf are not valid JSON
        if val ~= val or val == math.huge or val == -math.huge then return "null" end
        -- whole numbers without exponent / decimal point
        if val == math.floor(val) and math.abs(val) < 2^53 then
            return string.format("%d", val)
        end
        -- shortest form that round-trips (tostring keeps only ~14 digits)
        for _, fmt in ipairs({ "%.15g", "%.16g", "%.17g" }) do
            local s = string.format(fmt, val)
            if tonumber(s) == val then return s end
        end
        return string.format("%.17g", val)
    elseif t == "table" then
        if #val > 0 then
            local parts = {}
            for i = 1, #val do parts[i] = jsonEncode(val[i]) end
            return "[" .. table.concat(parts, ",") .. "]"
        end
        if next(val) == nil then return "[]" end
        local parts = {}
        for k, v in pairs(val) do
            parts[#parts + 1] = '"' .. jsonEscape(tostring(k)) .. '":' .. jsonEncode(v)
        end
        return "{" .. table.concat(parts, ",") .. "}"
    end
    return "null"
end

-- JSON-encodes an array field (e.g. "inferences", "sources") and stores it
-- as a string at unmapped.<field>.
local function addArrayFieldUnmapped(event, result, mapped_keys, field)
    local arr = getValue(event, field)
    if type(arr) == "table" and next(arr) ~= nil then
        setNestedField(result, "unmapped." .. field, jsonEncode(arr))
    end
    mapped_keys[field] = true
end

-- Read a value that may exist under two different key spellings — e.g.
-- Corelight's "id.orig_ep_uid" on most logs vs. the flat "orig_ep_uid" used
-- on _red-style (redacted/eCAP) logs.
local function getEitherValue(event, key1, key2)
    local v = getValue(event, key1)
    if v ~= nil and v ~= "" then return v end
    return getValue(event, key2)
end

-- "eCAP" endpoint-agent identity for the originating side
local function enrichSrcEndpointFromAgent(event, result, mapped_keys, observables)
    local ep_uid  = getEitherValue(event, "id.orig_ep_uid",  "orig_ep_uid")
    local ep_name = getEitherValue(event, "id.orig_ep_name", "orig_ep_name")
    if ep_name == nil or ep_name == "" then
        ep_name = getEitherValue(event, "id.orig_ep_source", "orig_ep_source")
    end
    if ep_uid ~= nil and not isPlaceholder(ep_uid) then
        setNestedField(result, "src_endpoint.uid", ep_uid)
    end
    if ep_name ~= nil and not isPlaceholder(ep_name) then
        setNestedField(result, "src_endpoint.hostname", ep_name)
    end
    mapped_keys["id.orig_ep_uid"] = true
    mapped_keys["orig_ep_uid"] = true
    mapped_keys["id.orig_ep_name"] = true
    mapped_keys["orig_ep_name"] = true
    mapped_keys["id.orig_ep_source"] = true
    mapped_keys["orig_ep_source"] = true
    if observables ~= nil and ep_uid ~= nil and not isPlaceholder(ep_uid) then
        addObservables(observables, "src_endpoint.uid", "Endpoint UID", 40, ep_uid)
    end
    return ep_uid, ep_name
end

-- eCAP endpoint-agent identity for the responding side
local function enrichDstEndpointFromAgent(event, result, mapped_keys)
    local ep_uid = getEitherValue(event, "id.resp_ep_uid", "resp_ep_uid")
    if ep_uid ~= nil and not isPlaceholder(ep_uid) then
        setNestedField(result, "dst_endpoint.uid", ep_uid)
    end
    mapped_keys["id.resp_ep_uid"] = true
    mapped_keys["resp_ep_uid"] = true
    return ep_uid
end


-- =========================================================
-- MODULE-SCOPE MAPPING TABLES
-- =========================================================

local CONN_STATE_MAP = {
    SF = 1, S1 = 1, S2 = 1, S3 = 1,
    S0 = 2, REJ = 2, RSTO = 2, RSTR = 2, RSTOS0 = 2,
    RSTRH = 2, SH = 2, SHR = 2,
    OTH = 99,
}

-- Per-state allow/deny verdict
local CONN_STATE_INFO = {
    SF     = { action_id = 1, action = "Allowed", severity_id = 1 },
    S1     = { action_id = 1, action = "Allowed", severity_id = 1 },
    S2     = { action_id = 1, action = "Allowed", severity_id = 1 },
    S3     = { action_id = 1, action = "Allowed", severity_id = 1 },
    OTH    = { action_id = 0, action = "Unknown", severity_id = 1 },
    S0     = { action_id = 0, action = "Unknown", severity_id = 2 },
    SH     = { action_id = 0, action = "Unknown", severity_id = 2 },
    REJ    = { action_id = 2, action = "Denied",  severity_id = 3 },
    RSTOS0 = { action_id = 2, action = "Denied",  severity_id = 3 },
    RSTRH  = { action_id = 2, action = "Denied",  severity_id = 3 },
    SHR    = { action_id = 2, action = "Denied",  severity_id = 3 },
    RSTO   = { action_id = 2, action = "Denied",  severity_id = 2 },
    RSTR   = { action_id = 2, action = "Denied",  severity_id = 2 },
}
local CONN_SEVERITY_CAPTIONS = { [1] = "Informational", [2] = "Low", [3] = "Medium" }

-- Returns action_id, action, severity_id, severity for a raw Zeek conn_state code.
local function connStateToActionSeverity(cs)
    if cs == nil or cs == "" then return 0, "Unknown", 1, "Informational" end
    local info = CONN_STATE_INFO[tostring(cs):upper()]
    if info == nil then return 0, "Unknown", 1, "Informational" end
    return info.action_id, info.action, info.severity_id, CONN_SEVERITY_CAPTIONS[info.severity_id] or "Informational"
end


local DNS_RCODE_MAP = {
    [0]=0,[1]=1,[2]=2,[3]=3,[4]=4,[5]=5,[6]=6,[7]=7,[8]=8,
    [9]=9,[10]=10,[11]=11,[16]=16,[17]=17,[18]=18,[19]=19,
    [20]=20,[21]=21,[22]=22,[23]=23,[24]=24, [25]=25
}

local DNS_RCODE_CAPTIONS = {
    [0]="NoError",[1]="FormError",[2]="ServError",[3]="NXDomain",[4]="NotImp",
    [5]="Refused",[6]="YXDomain",[7]="YXRRSet",[8]="NXRRSet",[9]="NotAuth",
    [10]="NotZone",[11]="DSOTYPENI",[16]="BADSIG_VERS",[17]="BADKEY",
    [18]="BADTIME",[19]="BADMODE",[20]="BADNAME",[21]="BADALG",
    [22]="BADTRUNC",[23]="BADCOOKIE",[24]="Unassigned", [25]="Reserved", [99]="Other",
}

local DNS_QTYPE_MAP = {
    A=1, NS=2, CNAME=5, SOA=6, PTR=12, MX=15, TXT=16, AAAA=28,
    SRV=33, DS=43, RRSIG=46, NSEC=47, DNSKEY=48, TLSA=52, HTTPS=65, ANY=255,
}

local FTP_CMD_MAP = {
    STOR=1, STOU=1, APPE=1,
    RETR=2,
    DELE=4,
    RNFR=5, RNTO=5,
    LIST=6, NLST=6, MLSD=6,
}

local FTP_ACT_CAPTIONS = {
    [0]="Unknown",[1]="Put",[2]="Get",[3]="Poll",[4]="Delete",[5]="Rename",[6]="List",[99]="Other",
}

local FTP_TYPE_CAPTIONS = {
    [400800]="FTP Activity: Unknown",[400801]="FTP Activity: Put",[400802]="FTP Activity: Get",
    [400804]="FTP Activity: Delete",[400805]="FTP Activity: Rename",[400806]="FTP Activity: List",
    [400899]="FTP Activity: Other",
}

local HTTP_METHOD_TYPE_MAP = {
    CONNECT=1, DELETE=2, GET=3, HEAD=4, OPTIONS=5,
    POST=6, PUT=7, TRACE=8, PATCH=9,
}

-- Classify an HTTP response code into OCSF status_id/status, and a matching
-- severity (server errors are more noteworthy than a plain 200).
local function httpStatusFromCode(code)
    local n = tonumber(code)
    if n == nil then return 0, "Unknown", 1, "Informational" end
    if n < 300 then return 1, "Success", 1, "Informational" end
    if n < 400 then return 2, "Redirect", 1, "Informational" end
    if n < 500 then return 3, "Client Error", 2, "Low" end
    return 4, "Server Error", 4, "High"
end

local HTTP_AGG_TYPE_CAPTIONS = {
    [400200]="HTTP Activity: Unknown",[400201]="HTTP Activity: Connect",
    [400202]="HTTP Activity: Delete",[400203]="HTTP Activity: Get",
    [400204]="HTTP Activity: Head",[400205]="HTTP Activity: Options",
    [400206]="HTTP Activity: Post",[400207]="HTTP Activity: Put",
    [400208]="HTTP Activity: Trace",[400209]="HTTP Activity: Patch",
    [400299]="HTTP Activity: Other",
}

-- HTTP method -> activity_id, activity_name, type_uid and type_name. Used by
-- the http and http2 handlers; http_agg and http_red apply the same mapping
-- inline. A placeholder method ("-" or empty) leaves the Unknown defaults.
local function setHttpActivity(result, method)
    if type(method) ~= "string" or isPlaceholder(method) then return end
    local method_upper = method:upper()
    local act_id = HTTP_METHOD_TYPE_MAP[method_upper] or 99
    local act_name = act_id == 99 and method
        or (method_upper:sub(1, 1) .. method_upper:sub(2):lower())
    local type_uid = 4002 * 100 + act_id
    result.activity_id   = act_id
    result.activity_name = act_name
    result.type_uid      = type_uid
    result.type_name     = HTTP_AGG_TYPE_CAPTIONS[type_uid] or ("HTTP Activity: " .. act_name)
end

local INTEL_INDICATOR_TYPE_MAP = {
    ["INTEL::ADDR"]=1, ["INTEL::DOMAIN"]=2, ["INTEL::URL"]=5,
    ["INTEL::SOFTWARE"]=6, ["INTEL::EMAIL"]=9, ["INTEL::CERT_HASH"]=7,
    ["INTEL::FILE_HASH"]=4, ["INTEL::FILE_NAME"]=11, ["INTEL::USER_NAME"]=99,
}


local KERB_REQUEST_TYPE_MAP = {
    AS=3, TGS=4,
}
local KERB_ACT_CAPTIONS = {
    [0]="Unknown",[1]="Logon",[2]="Logoff",[3]="Authentication Ticket",
    [4]="Service Ticket Request",[5]="Service Ticket Renew",[6]="Preauth",
    [7]="Account Switch",[99]="Other",
}

-- actual Zeek NoticeSeverity names, mapped to OCSF severity_id (emergency/alert -> Fatal, informational/debug -> Informational)
local NOTICE_SEV_MAP = {
    EMERGENCY=6, ALERT=6, CRITICAL=5, ERROR=4, WARNING=3,
    NOTIFICATION=2, INFORMATIONAL=1, DEBUG=1, OTHER=99, UNKNOWN=0,
}

-- same mapping but keyed by severity.level, since Zeek's scale is reversed vs OCSF's
local NOTICE_SEV_LEVEL_MAP = {
    [0]=6, [1]=6, [2]=5, [3]=4, [4]=3, [5]=2, [6]=1, [7]=1,
}

local NOTICE_ACTION_MAP = {
    ["NOTICE::ACTION_LOG"]=17, ["NOTICE::ACTION_DROP"]=6,
    ["NOTICE::ACTION_ALARM"]=19, ["NOTICE::ACTION_EMAIL"]=19,
}


local SHARE_TYPE_MAP = { DISK=1, PIPE=2, PRINT=3 }

local SURI_SEV_MAP = { [1]=5, [2]=4, [3]=3, [4]=2 }
local SURI_SEV_NAME_MAP = {
    MINOR=2, MAJOR=4, INFORMATIONAL=1, CRITICAL=5,
}

-- alert.action -> an allow/deny verdict + a matching status_id.
local SURI_ACTION_MAP = {
    allowed = { action_id = 1, action = "Allowed", status_id = 1 },
    allow   = { action_id = 1, action = "Allowed", status_id = 1 },
    alert   = { action_id = 1, action = "Allowed", status_id = 1 },
    blocked = { action_id = 2, action = "Denied",  status_id = 2 },
    block   = { action_id = 2, action = "Denied",  status_id = 2 },
    drop    = { action_id = 2, action = "Denied",  status_id = 2 },
}

local SMB_FILES_TYPE_CAPTIONS = {
    [400602]="SMB Activity: File Open",[400699]="SMB Activity: Other",[400600]="SMB Activity: Unknown",
}

local SSL_ACT_CAPTIONS = { [0]="Unknown", [1]="Open", [4]="Fail" }
local SSL_TYPE_CAPTIONS = {
    [400100]="Network Activity: Unknown",[400101]="Network Activity: Open",[400104]="Network Activity: Fail",
}

local STATUS_CAPTIONS = { [0]="Unknown", [1]="Success", [2]="Failure", [99]="Other" }

-- Older/weaker TLS versions carry more risk than current ones.
local TLS_VERSION_SEVERITY = {
    SSLV2 = 4, SSLV3 = 4, TLSV10 = 3, TLSV11 = 3, TLSV12 = 1, TLSV13 = 1,
}
local SEVERITY_ID_CAPTIONS = {
    [0]="Unknown",[1]="Informational",[2]="Low",[3]="Medium",[4]="High",[5]="Critical",[6]="Fatal",[99]="Other",
}

-- Combines TLS version, handshake success, and SNI/cert mismatch into one
-- severity, instead of a flat "Unknown"/0 for every TLS session.
local function tlsSeverity(tls_version, established, sni_matches_cert)
    local sev = 1
    if type(tls_version) == "string" then
        local norm = tls_version:upper():gsub("[%.%s]", "")
        sev = TLS_VERSION_SEVERITY[norm] or 1
    end
    if established == false or established == "false" then sev = math.max(sev, 2) end
    if sni_matches_cert == false or sni_matches_cert == "false" then sev = math.max(sev, 3) end
    return sev, SEVERITY_ID_CAPTIONS[sev] or "Informational"
end

-- =========================================================
-- EVENT TYPE HANDLERS
-- =========================================================

-- asset_classification

local ASSET_CLASSIFICATION_COPY_MAPPINGS = {
    { source = "ip",           target = "device.ip" },
    { source = "mac",          target = "device.mac" },
    { source = "brand",        target = "device.vendor_name" },
    { source = "model",        target = "device.model" },
    { source = "serial",       target = "device.hw_info.serial_number" },
    { source = "vendor_mac",   target = "device.mac_vendor" },
    { source = "_system_name", target = "metadata.log_provider" },
    { source = "_path",        target = "metadata.log_name" },
}

local function processAssetClassificationEvents(event)
    local result = {}
    result.class_uid     = 5001
    result.class_name    = "Device Inventory Info"
    result.category_uid  = 5
    result.category_name = "Discovery"
    result.activity_id   = 1
    result.activity_name = "Log"
    result.type_uid      = 500101
    result.type_name     = "Device Inventory Info: Log"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "asset_classification")
    setNestedField(result, "metadata.profiles", {"security_control"})
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    -- time: ts -> classification_ts -> _write_ts
    local ts_val = getValue(event, "ts")
    local time_ms = convertToMilliseconds(tostring(ts_val or ""))
    if time_ms == nil then
        time_ms = convertToMilliseconds(tostring(getValue(event, "classification_ts") or ""))
    end
    if time_ms == nil then
        time_ms = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    end
    if time_ms ~= nil then result.time = time_ms end

    -- metadata.logged_time
    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    -- classification_ts -> device.last_seen_time
    local cls_ts = convertToMilliseconds(tostring(getValue(event, "classification_ts") or ""))
    if cls_ts ~= nil then setNestedField(result, "device.last_seen_time", cls_ts) end

    local mapped_keys = {}
    for _, m in ipairs(ASSET_CLASSIFICATION_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["classification_ts"] = true
    mapped_keys["_write_ts"] = true

    local device_type_val = getValue(event, "device_type")
    if device_type_val ~= nil and device_type_val ~= "" then
        setNestedField(result, "device.type", device_type_val)
    end
    mapped_keys["device_type"] = true

    -- os object gated on os_name non-empty/non-placeholder
    local os_name = getValue(event, "os_name")
    if os_name ~= nil and not isPlaceholder(os_name) then
        setNestedField(result, "device.os.name", os_name)
        local os_ver = getValue(event, "os_ver")
        if os_ver ~= nil and os_ver ~= "" then setNestedField(result, "device.os.version", os_ver) end
        local os_build = getValue(event, "os_build")
        if os_build ~= nil and os_build ~= "" then setNestedField(result, "device.os.build", os_build) end
        mapped_keys["os_ver"] = true
        mapped_keys["os_build"] = true
    end
    mapped_keys["os_name"] = true

    -- sources -> JSON string at unmapped.sources
    addArrayFieldUnmapped(event, result, mapped_keys, "sources")

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- observables
    local observables = {}
    addObservables(observables, "device.ip", "IP Address", 2, getNestedField(result, "device.ip"))
    addObservables(observables, "device.mac", "MAC Address", 3, getNestedField(result, "device.mac"))
    addObservables(observables, "device.hw_info.serial_number", "Serial Number", 37, getNestedField(result, "device.hw_info.serial_number"))
    addObservables(observables, "device.os.name", "Other", 99, getNestedField(result, "device.os.name"))
    if #observables > 0 then result.observables = observables end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- conn helpers

local function connComputeDirection(event, result, src_field, dst_field)
    local dir_id, dir_name = localNetsDirection(event)
    if dir_id == nil then
        dir_id, dir_name = computeDirection(getValue(event, src_field), getValue(event, dst_field))
    end
    setNestedField(result, "connection_info.direction_id", dir_id)
    setNestedField(result, "connection_info.direction", dir_name)
end

local function connStateToStatus(cs)
    if cs == nil or cs == "" then return 0, "Unknown" end
    local sid = CONN_STATE_MAP[tostring(cs):upper()] or 99
    if sid == 0 then return 0, "Unknown"
    elseif sid == 1 then return 1, "Success"
    elseif sid == 2 then return 2, "Failure"
    else return 99, cs
    end
end

local function setCountryIfValid(event, result, src_field, target_path)
    local v = getValue(event, src_field)
    if v ~= nil and not isPlaceholder(v) then
        setNestedField(result, target_path, v)
    end
end

-- conn

local CONN_COPY_MAPPINGS = {
    { source = "id.orig_h",    target = "src_endpoint.ip" },
    { source = "orig_l2_addr", target = "src_endpoint.mac" },
    { source = "id.resp_h",    target = "dst_endpoint.ip" },
    { source = "resp_l2_addr", target = "dst_endpoint.mac" },
    { source = "community_id", target = "connection_info.community_uid" },
    { source = "uid",          target = "connection_info.uid" },
    { source = "history",      target = "connection_info.flag_history" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processConnEvents(event)
    local result = {}
    result.class_uid     = 4001
    result.class_name    = "Network Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 6
    result.activity_name = "Traffic"
    result.type_uid      = 400106
    result.type_name     = "Network Activity: Traffic"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "conn")
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local dur = tonumber(getValue(event, "duration"))
    if dur ~= nil then
        result.duration = math.floor(dur * 1000)
        if ts_val ~= nil then result.end_time = ts_val + result.duration end
    end

    local mapped_keys = {}
    for _, m in ipairs(CONN_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true
    mapped_keys["duration"] = true

    -- service 
    local svc = getValue(event, "service")
    if svc ~= nil and svc ~= "" then setNestedField(result, "app_protocol_name", svc) end
    mapped_keys["service"] = true

    -- proto lowercase
    local proto = getValue(event, "proto")
    if proto ~= nil and proto ~= "" then
        if type(proto) == "table" then proto = nil end
        if type(proto) ~= "string" then proto = tostring(proto or "") end
        setNestedField(result, "connection_info.protocol_name", proto:lower())
        mapped_keys["proto"] = true
    end

    -- ip_proto -> protocol_num
    local ip_proto = tonumber(getValue(event, "ip_proto"))
    if ip_proto ~= nil then
        setNestedField(result, "connection_info.protocol_num", ip_proto)
        mapped_keys["ip_proto"] = true
    end

    -- ports
    local orig_p = tonumber(getValue(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true
    local resp_p = tonumber(getValue(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction
    connComputeDirection(event, result, "id.orig_h", "id.resp_h")

    -- conn_state
    local cs = getValue(event, "conn_state")
    if cs ~= nil and cs ~= "" then
        local sid, sname = connStateToStatus(tostring(cs))
        setNestedField(result, "status_id", sid)
        setNestedField(result, "status", sname)
    else
        setNestedField(result, "status_id", 0)
        setNestedField(result, "status", "Unknown")
    end
    local act_id, act_name, sev_id, sev_name = connStateToActionSeverity(cs)
    setNestedField(result, "action_id", act_id)
    setNestedField(result, "action", act_name)
    setNestedField(result, "severity_id", sev_id)
    setNestedField(result, "severity", sev_name)

    -- traffic
    local ob = tonumber(getValue(event, "orig_bytes"))
    if ob ~= nil then setNestedField(result, "traffic.bytes_out", math.floor(ob)) end
    mapped_keys["orig_bytes"] = true
    local rb = tonumber(getValue(event, "resp_bytes"))
    if rb ~= nil then setNestedField(result, "traffic.bytes_in", math.floor(rb)) end
    mapped_keys["resp_bytes"] = true
    if ob ~= nil and rb ~= nil then setNestedField(result, "traffic.bytes", math.floor(ob) + math.floor(rb)) end
    local op = tonumber(getValue(event, "orig_pkts"))
    if op ~= nil then setNestedField(result, "traffic.packets_out", math.floor(op)) end
    mapped_keys["orig_pkts"] = true
    local rp = tonumber(getValue(event, "resp_pkts"))
    if rp ~= nil then setNestedField(result, "traffic.packets_in", math.floor(rp)) end
    mapped_keys["resp_pkts"] = true
    local mb = tonumber(getValue(event, "missed_bytes"))
    if mb ~= nil then setNestedField(result, "traffic.bytes_missed", math.floor(mb)) end
    mapped_keys["missed_bytes"] = true

    -- location
    setCountryIfValid(event, result, "orig_cc", "src_endpoint.location.country")
    mapped_keys["orig_cc"] = true
    setCountryIfValid(event, result, "resp_cc", "dst_endpoint.location.country")
    mapped_keys["resp_cc"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)
    enrichDstEndpointFromAgent(event, result, mapped_keys)

    -- Resolved hostnames
    local orig_names = getValue(event, "id.orig_h_name.vals")
    if type(orig_names) == "table" and orig_names[1] ~= nil and orig_names[1] ~= "" then
        setNestedField(result, "src_endpoint.hostname", orig_names[1])
    end
    local resp_names = getValue(event, "id.resp_h_name.vals")
    if type(resp_names) == "table" and resp_names[1] ~= nil and resp_names[1] ~= "" then
        setNestedField(result, "dst_endpoint.hostname", resp_names[1])
    end
    mapped_keys["id.orig_h_name.vals"] = true
    mapped_keys["id.resp_h_name.vals"] = true

    -- Human-readable one-line summary of the connection.
    setNestedField(result, "message",
        "conn " .. (getNestedField(result, "connection_info.protocol_name") or "?") .. " "
        .. (getNestedField(result, "src_endpoint.ip") or "?") .. " -> "
        .. (getNestedField(result, "dst_endpoint.ip") or "?"))

    -- observables
    local observables = {}
    addObservables(observables, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(observables, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    addObservables(observables, "src_endpoint.mac", "MAC Address", 3, getNestedField(result, "src_endpoint.mac"))
    addObservables(observables, "dst_endpoint.mac", "MAC Address", 3, getNestedField(result, "dst_endpoint.mac"))
    addObservables(observables, "connection_info.community_uid", "Other", 99, getNestedField(result, "connection_info.community_uid"))
    addObservables(observables, "connection_info.uid", "Other", 99, getNestedField(result, "connection_info.uid"))
    addObservables(observables, "src_endpoint.uid", "Endpoint UID", 40, getNestedField(result, "src_endpoint.uid"))
    addObservables(observables, "src_endpoint.hostname", "Hostname", 1, getNestedField(result, "src_endpoint.hostname"))
    addObservables(observables, "dst_endpoint.hostname", "Hostname", 1, getNestedField(result, "dst_endpoint.hostname"))
    if #observables > 0 then result.observables = observables end

    -- resp_inst.sg_ids[] -> JSON string at unmapped.resp_inst.sg_ids
    addArrayFieldUnmapped(event, result, mapped_keys, "resp_inst.sg_ids")

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- conn_agg

local CONN_AGG_COPY_MAPPINGS = {
    { source = "id.orig_h",    target = "src_endpoint.ip" },
    { source = "id.resp_h",    target = "dst_endpoint.ip" },
    { source = "histories",    target = "connection_info.flag_history" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processConnAggEvents(event)
    local result = {}
    result.class_uid     = 4001
    result.class_name    = "Network Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 6
    result.activity_name = "Traffic"
    result.type_uid      = 400106
    result.type_name     = "Network Activity: Traffic"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local ts_last = convertToMilliseconds(tostring(getValue(event, "ts_last") or ""))
    if ts_last ~= nil then result.end_time = ts_last end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local dur = tonumber(getValue(event, "duration"))
    if dur ~= nil then result.duration = math.floor(dur * 1000) end

    local mapped_keys = {}
    for _, m in ipairs(CONN_AGG_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["ts_last"] = true
    mapped_keys["_write_ts"] = true
    mapped_keys["duration"] = true

    -- service 
    local svc = getValue(event, "service")
    if svc ~= nil and svc ~= "" then setNestedField(result, "app_protocol_name", svc) end
    mapped_keys["service"] = true

    -- proto lowercase
    local proto = getValue(event, "proto")
    if proto ~= nil and proto ~= "" then
        if type(proto) == "table" then proto = nil end
        if type(proto) ~= "string" then proto = tostring(proto or "") end
        setNestedField(result, "connection_info.protocol_name", proto:lower())
        mapped_keys["proto"] = true
    end

    -- port
    local resp_p = tonumber(getValue(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction
    connComputeDirection(event, result, "id.orig_h", "id.resp_h")

    -- conn_states[] -> allow/deny verdict + a severity that reflects the outcome
    -- the first element is taken as representative
    local cs = firstScalar(getValue(event, "conn_states"))
    if cs ~= nil and cs ~= "" then
        local act_id, act_name, sev_id, sev_name = connStateToActionSeverity(cs)
        setNestedField(result, "action_id", act_id)
        setNestedField(result, "action", act_name)
        setNestedField(result, "severity_id", sev_id)
        setNestedField(result, "severity", sev_name)
    end
    mapped_keys["conn_states"] = true

    local cids = getValue(event, "community_ids")
    if type(cids) == "table" and cids ~= nil and cids ~= "" then
        setNestedField(result, "connection_info.community_uid", cids)
    end
    mapped_keys["community_ids"] = true

    -- uids[]
    local uids = getValue(event, "uids")
    if type(uids) == "table" and uids ~= nil and uids ~= "" then
        setNestedField(result, "connection_info.uid", uids)
    end
    mapped_keys["uids"] = true


    -- traffic
    local ob = tonumber(getValue(event, "orig_bytes"))
    if ob ~= nil then setNestedField(result, "traffic.bytes_out", math.floor(ob)) end
    mapped_keys["orig_bytes"] = true
    local rb = tonumber(getValue(event, "resp_bytes"))
    if rb ~= nil then setNestedField(result, "traffic.bytes_in", math.floor(rb)) end
    mapped_keys["resp_bytes"] = true
    local mb = tonumber(getValue(event, "missed_bytes"))
    if mb ~= nil then setNestedField(result, "traffic.bytes_missed", math.floor(mb)) end
    mapped_keys["missed_bytes"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)
    enrichDstEndpointFromAgent(event, result, mapped_keys)

    setNestedField(result, "message",
        "conn_agg " .. (getNestedField(result, "connection_info.protocol_name") or "?") .. " "
        .. (getNestedField(result, "src_endpoint.ip") or "?") .. " -> "
        .. (getNestedField(result, "dst_endpoint.ip") or "?"))

    -- observables
    local observables = {}
    addObservables(observables, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(observables, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    addObservables(observables, "connection_info.uid", "Other", 99, getNestedField(result, "connection_info.uid"))
    addObservables(observables, "connection_info.community_uid", "Other", 99, getNestedField(result, "connection_info.community_uid"))
    addObservables(observables, "src_endpoint.uid", "Endpoint UID", 40, getNestedField(result, "src_endpoint.uid"))
    if #observables > 0 then result.observables = observables end

    -- resp_inst.sg_ids[] -> JSON string at unmapped.resp_inst.sg_ids
    addArrayFieldUnmapped(event, result, mapped_keys, "resp_inst.sg_ids")

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- conn_long

local CONN_LONG_COPY_MAPPINGS = {
    { source = "uid",          target = "connection_info.uid" },
    { source = "community_id", target = "connection_info.community_uid" },
    { source = "history",      target = "connection_info.flag_history" },
    { source = "id.orig_h",   target = "src_endpoint.ip" },
    { source = "orig_l2_addr", target = "src_endpoint.mac" },
    { source = "id.resp_h",   target = "dst_endpoint.ip" },
    { source = "resp_l2_addr", target = "dst_endpoint.mac" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processConnLongEvents(event)
    local result = {}
    result.class_uid     = 4001
    result.class_name    = "Network Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 6
    result.activity_name = "Traffic"
    result.type_uid      = 400106
    result.type_name     = "Network Activity: Traffic"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local dur = tonumber(getValue(event, "duration"))
    if dur ~= nil then
        result.duration = math.floor(dur * 1000)
        if ts_val ~= nil then result.end_time = ts_val + result.duration end
    end

    local mapped_keys = {}
    for _, m in ipairs(CONN_LONG_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true
    mapped_keys["duration"] = true

    -- service
    local svc = getValue(event, "service")
    if svc ~= nil and svc ~= "" then setNestedField(result, "app_protocol_name", svc) end
    mapped_keys["service"] = true

    -- proto
    local proto = getValue(event, "proto")
    if proto ~= nil and proto ~= "" then
        if type(proto) == "table" then proto = nil end
        if type(proto) ~= "string" then proto = tostring(proto or "") end
        setNestedField(result, "connection_info.protocol_name", proto:lower())
        mapped_keys["proto"] = true
    end
    local ip_proto = tonumber(getValue(event, "ip_proto"))
    if ip_proto ~= nil then
        setNestedField(result, "connection_info.protocol_num", ip_proto)
        mapped_keys["ip_proto"] = true
    end

    -- ports
    local orig_p = tonumber(getValue(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true
    local resp_p = tonumber(getValue(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction
    connComputeDirection(event, result, "id.orig_h", "id.resp_h")

    -- conn_state -> allow/deny verdict + a severity that reflects the outcome
    local cs = getValue(event, "conn_state")
    if cs ~= nil and cs ~= "" then
        local act_id, act_name, sev_id, sev_name = connStateToActionSeverity(cs)
        setNestedField(result, "action_id", act_id)
        setNestedField(result, "action", act_name)
        setNestedField(result, "severity_id", sev_id)
        setNestedField(result, "severity", sev_name)
    end

    -- traffic
    local ob = tonumber(getValue(event, "orig_bytes"))
    if ob ~= nil then setNestedField(result, "traffic.bytes_out", math.floor(ob)) end
    mapped_keys["orig_bytes"] = true
    local rb = tonumber(getValue(event, "resp_bytes"))
    if rb ~= nil then setNestedField(result, "traffic.bytes_in", math.floor(rb)) end
    mapped_keys["resp_bytes"] = true
    if ob ~= nil and rb ~= nil then setNestedField(result, "traffic.bytes", math.floor(ob) + math.floor(rb)) end
    local op = tonumber(getValue(event, "orig_pkts"))
    if op ~= nil then setNestedField(result, "traffic.packets_out", math.floor(op)) end
    mapped_keys["orig_pkts"] = true
    local rp = tonumber(getValue(event, "resp_pkts"))
    if rp ~= nil then setNestedField(result, "traffic.packets_in", math.floor(rp)) end
    mapped_keys["resp_pkts"] = true
    local mb_val = tonumber(getValue(event, "missed_bytes"))
    if mb_val ~= nil then setNestedField(result, "traffic.bytes_missed", math.floor(mb_val)) end
    mapped_keys["missed_bytes"] = true

    -- location
    setCountryIfValid(event, result, "orig_cc", "src_endpoint.location.country")
    mapped_keys["orig_cc"] = true
    setCountryIfValid(event, result, "resp_cc", "dst_endpoint.location.country")
    mapped_keys["resp_cc"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)
    enrichDstEndpointFromAgent(event, result, mapped_keys)

    local orig_names = getValue(event, "id.orig_h_name.vals")
    if type(orig_names) == "table" and orig_names[1] ~= nil and orig_names[1] ~= "" then
        setNestedField(result, "src_endpoint.hostname", orig_names[1])
    end
    local resp_names = getValue(event, "id.resp_h_name.vals")
    if type(resp_names) == "table" and resp_names[1] ~= nil and resp_names[1] ~= "" then
        setNestedField(result, "dst_endpoint.hostname", resp_names[1])
    end
    mapped_keys["id.orig_h_name.vals"] = true
    mapped_keys["id.resp_h_name.vals"] = true

    setNestedField(result, "message",
        "conn_long " .. (getNestedField(result, "connection_info.protocol_name") or "?") .. " "
        .. (getNestedField(result, "src_endpoint.ip") or "?") .. " -> "
        .. (getNestedField(result, "dst_endpoint.ip") or "?"))

    -- observables
    local observables = {}
    addObservables(observables, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(observables, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    addObservables(observables, "src_endpoint.mac", "MAC Address", 3, getNestedField(result, "src_endpoint.mac"))
    addObservables(observables, "dst_endpoint.mac", "MAC Address", 3, getNestedField(result, "dst_endpoint.mac"))
    addObservables(observables, "connection_info.uid", "Other", 99, getNestedField(result, "connection_info.uid"))
    addObservables(observables, "connection_info.community_uid", "Other", 99, getNestedField(result, "connection_info.community_uid"))
    addObservables(observables, "src_endpoint.uid", "Endpoint UID", 40, getNestedField(result, "src_endpoint.uid"))
    addObservables(observables, "src_endpoint.hostname", "Hostname", 1, getNestedField(result, "src_endpoint.hostname"))
    addObservables(observables, "dst_endpoint.hostname", "Hostname", 1, getNestedField(result, "dst_endpoint.hostname"))
    if #observables > 0 then result.observables = observables end

    -- resp_inst.sg_ids[] -> JSON string at unmapped.resp_inst.sg_ids
    addArrayFieldUnmapped(event, result, mapped_keys, "resp_inst.sg_ids")

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- conn_red

local CONN_RED_COPY_MAPPINGS = {
    { source = "id.orig_h",    target = "src_endpoint.ip" },
    { source = "orig_l2_addr", target = "src_endpoint.mac" },
    { source = "id.resp_h",    target = "dst_endpoint.ip" },
    { source = "resp_l2_addr", target = "dst_endpoint.mac" },
    { source = "uid",          target = "connection_info.uid" },
    { source = "community_id", target = "connection_info.community_uid" },
    { source = "history",      target = "connection_info.flag_history" },
    { source = "_system_name", target = "metadata.log_provider" },
    { source = "_path",        target = "metadata.log_name" },
}

local function processConnRedEvents(event)
    local result = {}
    result.class_uid     = 4001
    result.class_name    = "Network Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 6
    result.activity_name = "Traffic"
    result.type_uid      = 400106
    result.type_name     = "Network Activity: Traffic"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local dur = tonumber(getValue(event, "duration"))
    if dur ~= nil then
        result.duration = math.floor(dur * 1000 + 0.5)
        if ts_val ~= nil then result.end_time = ts_val + result.duration end
    end

    local mapped_keys = {}
    for _, m in ipairs(CONN_RED_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true
    mapped_keys["duration"] = true

    -- service
    local svc = getValue(event, "service")
    if svc ~= nil and svc ~= "" then setNestedField(result, "app_protocol_name", svc) end
    mapped_keys["service"] = true

    -- proto
    local proto = getValue(event, "proto")
    if proto ~= nil and proto ~= "" then
        if type(proto) == "table" then proto = nil end
        if type(proto) ~= "string" then proto = tostring(proto or "") end
        setNestedField(result, "connection_info.protocol_name", proto:lower())
        mapped_keys["proto"] = true
    end

    -- ports
    local orig_p = tonumber(getValue(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true
    local resp_p = tonumber(getValue(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction
    connComputeDirection(event, result, "id.orig_h", "id.resp_h")

    -- conn_state -> allow/deny verdict + a severity that reflects the outcome
    local cs = getValue(event, "conn_state")
    if cs ~= nil and cs ~= "" then
        local act_id, act_name, sev_id, sev_name = connStateToActionSeverity(cs)
        setNestedField(result, "action_id", act_id)
        setNestedField(result, "action", act_name)
        setNestedField(result, "severity_id", sev_id)
        setNestedField(result, "severity", sev_name)
    end

    -- traffic
    local ob = tonumber(getValue(event, "orig_bytes"))
    if ob ~= nil then setNestedField(result, "traffic.bytes_out", math.floor(ob)) end
    mapped_keys["orig_bytes"] = true
    local rb = tonumber(getValue(event, "resp_bytes"))
    if rb ~= nil then setNestedField(result, "traffic.bytes_in", math.floor(rb)) end
    mapped_keys["resp_bytes"] = true
    if ob ~= nil and rb ~= nil then setNestedField(result, "traffic.bytes", math.floor(ob) + math.floor(rb)) end
    local op = tonumber(getValue(event, "orig_pkts"))
    if op ~= nil then setNestedField(result, "traffic.packets_out", math.floor(op)) end
    mapped_keys["orig_pkts"] = true
    local rp = tonumber(getValue(event, "resp_pkts"))
    if rp ~= nil then setNestedField(result, "traffic.packets_in", math.floor(rp)) end
    mapped_keys["resp_pkts"] = true
    local mb_val = tonumber(getValue(event, "missed_bytes"))
    if mb_val ~= nil then setNestedField(result, "traffic.bytes_missed", math.floor(mb_val)) end
    mapped_keys["missed_bytes"] = true

    -- location
    setCountryIfValid(event, result, "orig_cc", "src_endpoint.location.country")
    mapped_keys["orig_cc"] = true
    setCountryIfValid(event, result, "resp_cc", "dst_endpoint.location.country")
    mapped_keys["resp_cc"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)
    enrichDstEndpointFromAgent(event, result, mapped_keys)

    local orig_names = getValue(event, "id.orig_h_name.vals")
    if type(orig_names) == "table" and orig_names[1] ~= nil and orig_names[1] ~= "" then
        setNestedField(result, "src_endpoint.hostname", orig_names[1])
    end
    local resp_names = getValue(event, "id.resp_h_name.vals")
    if type(resp_names) == "table" and resp_names[1] ~= nil and resp_names[1] ~= "" then
        setNestedField(result, "dst_endpoint.hostname", resp_names[1])
    end
    mapped_keys["id.orig_h_name.vals"] = true
    mapped_keys["id.resp_h_name.vals"] = true

    setNestedField(result, "message",
        "conn_red " .. (getNestedField(result, "connection_info.protocol_name") or "?") .. " "
        .. (getNestedField(result, "src_endpoint.ip") or "?") .. " -> "
        .. (getNestedField(result, "dst_endpoint.ip") or "?"))

    -- observables
    local observables = {}
    addObservables(observables, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(observables, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    addObservables(observables, "src_endpoint.mac", "MAC Address", 3, getNestedField(result, "src_endpoint.mac"))
    addObservables(observables, "dst_endpoint.mac", "MAC Address", 3, getNestedField(result, "dst_endpoint.mac"))
    addObservables(observables, "src_endpoint.hostname", "Hostname", 1, getNestedField(result, "src_endpoint.hostname"))
    addObservables(observables, "dst_endpoint.hostname", "Hostname", 1, getNestedField(result, "dst_endpoint.hostname"))
    addObservables(observables, "connection_info.uid", "Other", 99, getNestedField(result, "connection_info.uid"))
    addObservables(observables, "connection_info.community_uid", "Other", 99, getNestedField(result, "connection_info.community_uid"))
    addObservables(observables, "src_endpoint.uid", "Endpoint UID", 40, getNestedField(result, "src_endpoint.uid"))
    if #observables > 0 then result.observables = observables end

    -- resp_inst.sg_ids[] -> JSON string at unmapped.resp_inst.sg_ids
    addArrayFieldUnmapped(event, result, mapped_keys, "resp_inst.sg_ids")

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- corelight_metrics_disk

local CORELIGHT_METRICS_DISK_COPY_MAPPINGS = {
    { source = "_path",        target = "metadata.log_name" },
}

local function processCorelightMetricsDiskEvents(event)
    local result = {}
    result.class_uid     = 0
    result.class_name    = "Base Event"
    result.category_uid  = 0
    result.category_name = "Uncategorized"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 0
    result.type_name     = "Base Event: Unknown"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "corelight_metrics_disk")
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", { "host" })

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local sys_name = getValue(event, "_system_name")
    if sys_name ~= nil and not isPlaceholder(sys_name) then
        setNestedField(result, "metadata.log_provider", sys_name)
    end

    local mapped_keys = {}
    for _, m in ipairs(CORELIGHT_METRICS_DISK_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true
    mapped_keys["_system_name"] = true

    -- The remaining fields are placed under unmapped.*, without zero-valued
    -- counters (see withoutZeroCounters).
    copyUnmappedFields(withoutZeroCounters(event), result, mapped_keys)
    return result
end

-- dns helpers

local function dnsRcodeToId(rcode_val)
    if rcode_val == nil or rcode_val == "" or isPlaceholder(tostring(rcode_val)) then return 0 end
    local n = tonumber(rcode_val)
    if n == nil then return 99 end
    local mapped = DNS_RCODE_MAP[n]
    if mapped ~= nil then return mapped end
    return 99
end

local function dnsRcodeCaption(rcode_id)
    return DNS_RCODE_CAPTIONS[rcode_id] or "Other"
end

-- True for an IPv4 or IPv6 address literal, so only A/AAAA answers (not
-- CNAME/PTR/TXT rdata) become IP Address observables.
local function dnsIsIPAddress(s)
    if type(s) ~= "string" then return false end
    if s:match("^%d+%.%d+%.%d+%.%d+$") then return true end
    return s:find(":", 1, true) ~= nil and s:match("^[%x:%.]+$") ~= nil
end

-- answers[] (+ optional TTLs[] merged by position) -> answers, stored as a
-- JSON string of [{rdata, ttl}] in every dns variant.
local function dnsBuildAnswers(event, result, src_field, ttl_field)
    local answers_raw = getValue(event, src_field)
    if type(answers_raw) ~= "table" or #answers_raw == 0 then return end
    local ttls = ttl_field and getValue(event, ttl_field)
    if type(ttls) ~= "table" then ttls = {} end
    local answers = {}
    for i, v in ipairs(answers_raw) do
        if v ~= nil and v ~= "" then
            answers[#answers + 1] = { rdata = tostring(v), ttl = ttls[i] }
        end
    end
    if #answers > 0 then result.answers = jsonEncode(answers) end
end

-- IP-shaped answers (A/AAAA) -> answers.rdata IP Address observables, read
-- from the event since result.answers is a JSON string.
local function dnsAddAnswerObservables(observables, event, src_field)
    local answers_raw = getValue(event, src_field)
    if type(answers_raw) ~= "table" then return end
    for _, a in ipairs(answers_raw) do
        if dnsIsIPAddress(a) then
            addObservables(observables, "answers.rdata", "IP Address", 2, a)
        end
    end
end

-- dns

local DNS_COPY_MAPPINGS = {
    { source = "id.orig_h",    target = "src_endpoint.ip" },
    { source = "id.resp_h",    target = "dst_endpoint.ip" },
    { source = "uid",          target = "connection_info.uid" },
    { source = "qtype_name",   target = "query.type" },
    { source = "qclass_name",  target = "query.class" },
    { source = "rcode_name",   target = "status_detail" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processDnsEvents(event)
    local result = {}
    result.class_uid     = 4003
    result.class_name    = "DNS Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 6
    result.activity_name = "Traffic"
    result.type_uid      = 400306
    result.type_name     = "DNS Activity: Traffic"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "dns")
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(DNS_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- ports
    local orig_p = tonumber(getValue(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true
    local resp_p = tonumber(getValue(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- proto -> protocol_name + protocol_num
    local proto = getValue(event, "proto")
    local proto_num = 0
    if proto ~= nil and proto ~= "" then
        if type(proto) == "table" then proto = nil end
        if type(proto) ~= "string" then proto = tostring(proto or "") end
        local p = proto:lower()
        setNestedField(result, "connection_info.protocol_name", p)
        if p == "tcp" then proto_num = 6
        elseif p == "udp" then proto_num = 17
        elseif p == "icmp" then proto_num = 1 end
        mapped_keys["proto"] = true
    end
    setNestedField(result, "connection_info.protocol_num", proto_num)

    -- direction
    connComputeDirection(event, result, "id.orig_h", "id.resp_h")

    -- rcode -> rcode_id, rcode caption, status_id, status
    local rcode_raw = getValue(event, "rcode")
    local rcode_id = dnsRcodeToId(rcode_raw)
    setNestedField(result, "rcode_id", rcode_id)
    setNestedField(result, "rcode", dnsRcodeCaption(rcode_id))
    mapped_keys["rcode"] = true

    -- rejected -> allow/deny verdict, and a severity that reflects lookup
    -- failures / blocked queries instead of a flat "Informational" always.
    local rejected = getValue(event, "rejected")
    local dns_sev_id, dns_sev_name = 1, "Informational"
    if rcode_id == 2 then dns_sev_id, dns_sev_name = 3, "Medium"       -- ServFail
    elseif rcode_id == 3 then dns_sev_id, dns_sev_name = 2, "Low" end  -- NXDomain
    local is_rejected = (rejected == true or rejected == "true")
    setNestedField(result, "action_id", is_rejected and 2 or 1)
    setNestedField(result, "action", is_rejected and "Denied" or "Allowed")
    if is_rejected and dns_sev_id < 3 then dns_sev_id, dns_sev_name = 3, "Medium" end
    setNestedField(result, "severity_id", dns_sev_id)
    setNestedField(result, "severity", dns_sev_name)
    -- mapped_keys["rejected"] = true -> Here, we are not marking it as true because we need it for dashboard visualization

    -- query
    local query_val = getValue(event, "query")
    if query_val ~= nil and query_val ~= "" then
        setNestedField(result, "query.hostname", query_val)
    end
    mapped_keys["query"] = true

    local qtype_name = getValue(event, "qtype_name")
    local qtype_id = getValue(event, "qtype")
    if not qtype_id and type(qtype_name) == "string" then
        qtype_id = DNS_QTYPE_MAP[qtype_name:upper()]
    end
    mapped_keys["qtype"] = true

    -- trans_id -> query.packet_uid
    local trans_id = tonumber(getValue(event, "trans_id"))
    if trans_id ~= nil then setNestedField(result, "query.packet_uid", trans_id) end
    mapped_keys["trans_id"] = true

    -- answers[] + TTLs[] -> answers (JSON string)
    dnsBuildAnswers(event, result, "answers", "TTLs")
    mapped_keys["answers"] = true
    mapped_keys["TTLs"] = true

    -- id.vlan -> src_endpoint.vlan_uid
    local id_vlan = getValue(event, "id.vlan")
    if id_vlan ~= nil and id_vlan ~= "" then
        setNestedField(result, "src_endpoint.vlan_uid", tostring(id_vlan))
        mapped_keys["id.vlan"] = true
    end

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)
    enrichDstEndpointFromAgent(event, result, mapped_keys)

    -- one-line summary.
    setNestedField(result, "message",
        "dns " .. (getNestedField(result, "query.hostname") or "?") .. " -> "
        .. (getNestedField(result, "rcode") or "?"))

    -- observables
    local observables = {}
    addObservables(observables, "query.hostname", "Hostname", 1, getNestedField(result, "query.hostname"))
    addObservables(observables, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(observables, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    dnsAddAnswerObservables(observables, event, "answers")
    if #observables > 0 then result.observables = observables end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- dns_agg

local DNS_AGG_COPY_MAPPINGS = {
    { source = "id.orig_h",    target = "src_endpoint.ip" },
    { source = "qtype_name",   target = "query.type" },
    { source = "rcode_name",   target = "status_detail" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processDnsAggEvents(event)
    local result = {}
    result.class_uid     = 4003
    result.class_name    = "DNS Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 6
    result.activity_name = "Traffic"
    result.type_uid      = 400306
    result.type_name     = "DNS Activity: Traffic"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "dns_agg")
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})
    setNestedField(result, "dst_endpoint.svc_name", "dns")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local ts_last = convertToMilliseconds(tostring(getValue(event, "ts_last") or ""))
    if ts_last ~= nil then result.end_time = ts_last end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(DNS_AGG_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["ts_last"] = true
    mapped_keys["_write_ts"] = true

    -- id.resp_p -> dst_endpoint.port
    local resp_p = tonumber(getValue(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- rcode -> rcode_id, rcode, status
    local rcode_raw = getValue(event, "rcode")
    local rcode_id
    if rcode_raw == nil or rcode_raw == "" or isPlaceholder(tostring(rcode_raw)) then
        rcode_id = 0
    else
        rcode_id = dnsRcodeToId(rcode_raw)
    end
    setNestedField(result, "rcode_id", rcode_id)
    setNestedField(result, "rcode", dnsRcodeCaption(rcode_id))
    mapped_keys["rcode"] = true

    -- rejected -> allow/deny verdict, and a severity that reflects lookup
    -- failures / blocked queries instead of a flat "Informational" always.
    local rejected = getValue(event, "rejected")
    local dns_sev_id, dns_sev_name = 1, "Informational"
    if rcode_id == 2 then dns_sev_id, dns_sev_name = 3, "Medium"
    elseif rcode_id == 3 then dns_sev_id, dns_sev_name = 2, "Low" end
    local is_rejected = (rejected == true or rejected == "true")
    setNestedField(result, "action_id", is_rejected and 2 or 1)
    setNestedField(result, "action", is_rejected and "Denied" or "Allowed")
    if is_rejected and dns_sev_id < 3 then dns_sev_id, dns_sev_name = 3, "Medium" end
    setNestedField(result, "severity_id", dns_sev_id)
    setNestedField(result, "severity", dns_sev_name)
    mapped_keys["rejected"] = true

    -- query.hostname
    local query_val = getValue(event, "query")
    if query_val ~= nil and query_val ~= "" then
        setNestedField(result, "query.hostname", query_val)
    end
    mapped_keys["query"] = true

    local qtype_name = getValue(event, "qtype_name")
    local qtype_id = getValue(event, "qtype")
    if not qtype_id and type(qtype_name) == "string" then
        qtype_id = DNS_QTYPE_MAP[qtype_name:upper()]
    end
    mapped_keys["qtype"] = true

    -- answers[] -> answers (JSON string)
    dnsBuildAnswers(event, result, "answers")
    mapped_keys["answers"] = true

    -- count
    local cnt = tonumber(getValue(event, "count"))
    if cnt ~= nil then result.count = math.floor(cnt) end
    mapped_keys["count"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity 
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)

    -- one-line summary.
    setNestedField(result, "message",
        "dns_agg " .. (getNestedField(result, "query.hostname") or "?") .. " -> "
        .. (getNestedField(result, "rcode") or "?"))

    
    local observables = {}
    -- observables
    addObservables(observables, "query.hostname", "Hostname", 1, getNestedField(result, "query.hostname"))
    addObservables(observables, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    dnsAddAnswerObservables(observables, event, "answers")
    if #observables > 0 then result.observables = observables end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- dns_red

local DNS_RED_COPY_MAPPINGS = {
    { source = "uid",          target = "connection_info.uid" },
    { source = "id.orig_h",   target = "src_endpoint.ip" },
    { source = "id.resp_h",   target = "dst_endpoint.ip" },
    { source = "query",        target = "query.hostname" },
    { source = "qtype_name",   target = "query.type" },
    { source = "_system_name", target = "metadata.log_provider" },
    { source = "_path",        target = "metadata.log_name" },
}

local function processDnsRedEvents(event)
    local result = {}
    result.class_uid     = 4003
    result.class_name    = "DNS Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 6
    result.activity_name = "Traffic"
    result.type_uid      = 400306
    result.type_name     = "DNS Activity: Traffic"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(DNS_RED_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- ports
    local orig_p = tonumber(getValue(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true
    local resp_p = tonumber(getValue(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction
    connComputeDirection(event, result, "id.orig_h", "id.resp_h")

    -- rcode -> rcode_id, rcode caption, status
    local rcode_raw = getValue(event, "rcode")
    local rcode_id = dnsRcodeToId(rcode_raw)
    setNestedField(result, "rcode_id", rcode_id)
        setNestedField(result, "rcode", dnsRcodeCaption(rcode_id))
    mapped_keys["rcode"] = true

    -- answers[] -> answers (JSON string)
    dnsBuildAnswers(event, result, "answers")
    mapped_keys["answers"] = true

    -- count from num
    local num_val = tonumber(getValue(event, "num"))
    if num_val ~= nil then result.count = math.floor(num_val) end
    mapped_keys["num"] = true

    -- id.vlan -> src_endpoint.vlan_uid
    local id_vlan = getValue(event, "id.vlan")
    if id_vlan ~= nil and id_vlan ~= "" then
        setNestedField(result, "src_endpoint.vlan_uid", tostring(id_vlan))
        mapped_keys["id.vlan"] = true
    end

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)
    enrichDstEndpointFromAgent(event, result, mapped_keys)

    -- one-line summary.
    setNestedField(result, "message",
        "dns_red " .. (getNestedField(result, "query.hostname") or "?") .. " -> "
        .. (getNestedField(result, "rcode") or "?"))

    -- observables
    local observables = {}
    addObservables(observables, "query.hostname", "Hostname", 1, getNestedField(result, "query.hostname"))
    addObservables(observables, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(observables, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    dnsAddAnswerObservables(observables, event, "answers")
    if #observables > 0 then result.observables = observables end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- etc_viz

local ETC_VIZ_COPY_MAPPINGS = {
    { source = "uid",          target = "connection_info.uid" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processEtcVizEvents(event)
    local result = {}
    result.class_uid     = 4001
    result.class_name    = "Network Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 6
    result.activity_name = "Traffic"
    result.type_uid      = 400106
    result.type_name     = "Network Activity: Traffic"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})
    setNestedField(result, "connection_info.direction_id", 0)
    setNestedField(result, "connection_info.direction", "Unknown")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(ETC_VIZ_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- server_a -> dst_endpoint.ip
    local server_a = getValue(event, "server_a")
    if server_a ~= nil and server_a ~= "" then
        setNestedField(result, "dst_endpoint.ip", server_a)
        mapped_keys["server_a"] = true
    end

    -- server_p -> dst_endpoint.port
    local server_p = tonumber(getValue(event, "server_p"))
    if server_p ~= nil then setNestedField(result, "dst_endpoint.port", server_p) end
    mapped_keys["server_p"] = true

    -- service -> app_protocol_name
    local svc = getValue(event, "service")
    if svc ~= nil then
        setNestedField(result, "app_protocol_name", svc)
        mapped_keys["service"] = true
    end

    -- traffic
    local c2s = tonumber(getValue(event, "c2s_viz.size"))
    if c2s ~= nil then setNestedField(result, "traffic.bytes_out", math.floor(c2s)) end
    mapped_keys["c2s_viz.size"] = true
    local s2c = tonumber(getValue(event, "s2c_viz.size"))
    if s2c ~= nil then setNestedField(result, "traffic.bytes_in", math.floor(s2c)) end
    mapped_keys["s2c_viz.size"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- observables
    local observables = {}
    addObservables(observables, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    if #observables > 0 then result.observables = observables end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- files helpers

local function buildFileHashes(event, result, fields)
    -- fields: list of { src_field, hash_type }
    -- Each goes into a separate element of file.hashes[]
    local hashes = {}
    for _, f in ipairs(fields) do
        local v = getValue(event, f.src)
        if v ~= nil and v ~= "" then
            hashes[#hashes + 1] = { value = tostring(v), algorithm = f.alg, algorithm_id = f.alg_id }
        end
    end
    if #hashes > 0 then
        if result.file == nil then result.file = {} end
        result.file.hashes = hashes
    end
end

local FILE_HASH_FIELDS = {
    { src = "md5",    alg = "MD5",    alg_id = 1 },
    { src = "sha1",   alg = "SHA-1",  alg_id = 2 },
    { src = "sha256", alg = "SHA-256",alg_id = 3 },
}

-- files

local FILES_COPY_MAPPINGS = {
    { source = "uid",          target = "connection_info.uid" },
    { source = "fuid",         target = "file.uid" },
    { source = "filename",     target = "file.name" },
    { source = "mime_type",    target = "file.mime_type" },
    { source = "total_bytes",  target = "file.size" },
    { source = "_system_name", target = "metadata.log_provider" },
    { source = "_path",        target = "metadata.log_name" },

}

local function processFilesEvents(event)
    local result = {}
    result.class_uid     = 6006
    result.class_name    = "File Hosting Activity"
    result.category_uid  = 6
    result.category_name = "Application Activity"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 600600
    result.type_name     = "File Hosting Activity: Unknown"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local dur = tonumber(getValue(event, "duration"))
    if dur ~= nil then result.duration = math.floor(dur * 1000) end

    local mapped_keys = {}
    for _, m in ipairs(FILES_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true
    mapped_keys["duration"] = true

    -- src_endpoint: id.orig_h -> tx_hosts[] fallback
    local orig_h = getValue(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then
        setNestedField(result, "src_endpoint.ip", orig_h)
    else
        local tx = getValue(event, "tx_hosts")
        if type(tx) == "table" and tx[1] ~= nil and tx[1] ~= "" then
            setNestedField(result, "src_endpoint.ip", tx[1])
        end
    end
    mapped_keys["id.orig_h"] = true

    -- dst_endpoint: id.resp_h -> rx_hosts[] fallback
    local resp_h = getValue(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then
        setNestedField(result, "dst_endpoint.ip", resp_h)
    else
        local rx = getValue(event, "rx_hosts")
        if type(rx) == "table" and rx[1] ~= nil and rx[1] ~= "" then
            setNestedField(result, "dst_endpoint.ip", rx[1])
        end
    end
    mapped_keys["id.resp_h"] = true

    -- ports
    local orig_p = tonumber(getValue(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true
    local resp_p = tonumber(getValue(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction
    local src_ip = getNestedField(result, "src_endpoint.ip")
    local dst_ip = getNestedField(result, "dst_endpoint.ip")
    local dir_id, dir_name = computeDirection(src_ip, dst_ip)
    setNestedField(result, "connection_info.direction_id", dir_id)
    setNestedField(result, "connection_info.direction", dir_name)

    -- file hashes
    buildFileHashes(event, result, FILE_HASH_FIELDS)
    mapped_keys["md5"] = true
    mapped_keys["sha1"] = true
    mapped_keys["sha256"] = true

    -- is_orig -> upload/download direction, used in the message only (the
    -- class stays Network Activity / Traffic per our OCSF mapping).
    local is_orig = getValue(event, "is_orig")
    local direction_word = "transferred"
    if is_orig == true or is_orig == "true" then direction_word = "uploaded"
    elseif is_orig == false or is_orig == "false" then direction_word = "downloaded" end
    mapped_keys["is_orig"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)

    -- one-line summary
    local source_val = getValue(event, "source")
    local observables = {}
    setNestedField(result, "message",
        "File " .. direction_word .. " via " .. (source_val or "?") .. ": "
        .. (getNestedField(result, "file.mime_type") or "unknown"))

    -- observables
    addObservables(observables, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(observables, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    if #observables > 0 then result.observables = observables end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- files_agg

local FILES_AGG_COPY_MAPPINGS = {
    { source = "id.orig_h",    target = "src_endpoint.ip" },
    { source = "id.resp_h",    target = "dst_endpoint.ip" },
    { source = "fuid",         target = "file.uid" },
    { source = "filename",     target = "file.name" },
    { source = "mime_type",    target = "file.mime_type" },
    { source = "total_bytes",  target = "file.size" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processFilesAggEvents(event)
    local result = {}
    result.class_uid     = 6006
    result.class_name    = "File Hosting Activity"
    result.category_uid  = 6
    result.category_name = "Application Activity"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 600600
    result.type_name     = "File Hosting Activity: Unknown"
    result.severity_id   = 0
    result.severity      = "Unknown"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local dur = tonumber(getValue(event, "duration"))
    if dur ~= nil then result.duration = math.floor(dur * 1000 + 0.5) end

    local mapped_keys = {}
    for _, m in ipairs(FILES_AGG_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true
    mapped_keys["duration"] = true

    -- direction
    local src_ip = getValue(event, "id.orig_h")
    local dst_ip = getValue(event, "id.resp_h")
    local dir_id, dir_name = computeDirection(src_ip, dst_ip)
    setNestedField(result, "connection_info.direction_id", dir_id)
    setNestedField(result, "connection_info.direction", dir_name)

    -- uids[]
    local uids_val = getValue(event, "uids")
    if type(uids_val) == "table" and uids_val ~= nil and uids_val ~= "" then
        setNestedField(result, "connection_info.uid", uids_val)
    end
    mapped_keys["uids"] = true

    -- count
    local cnt = tonumber(getValue(event, "count"))
    if cnt ~= nil then result.count = math.floor(cnt) end
    mapped_keys["count"] = true

    -- missing_bytes -> traffic.bytes_missed
    local miss = tonumber(getValue(event, "missing_bytes"))
    if miss ~= nil then setNestedField(result, "traffic.bytes_missed", math.floor(miss)) end
    mapped_keys["missing_bytes"] = true
    if miss ~= nil and miss > 0 then
        setNestedField(result, "severity_id", 2)
        setNestedField(result, "severity", "Low")
    else
        setNestedField(result, "severity_id", 1)
        setNestedField(result, "severity", "Informational")
    end

    -- file hashes
    buildFileHashes(event, result, FILE_HASH_FIELDS)
    mapped_keys["md5"] = true
    mapped_keys["sha1"] = true
    mapped_keys["sha256"] = true

    -- is_orig -> upload/download direction (message only)
    local is_orig = getValue(event, "is_orig")
    local direction_word = "transferred"
    if is_orig == true or is_orig == "true" then direction_word = "uploaded"
    elseif is_orig == false or is_orig == "false" then direction_word = "downloaded" end
    mapped_keys["is_orig"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)

    -- one-line summary
    local source_val = getValue(event, "source")
    setNestedField(result, "message",
        "File " .. direction_word .. " via " .. (source_val or "?") .. ": "
        .. (getNestedField(result, "file.mime_type") or "unknown"))

    -- observables
    local observables = {}
    addObservables(observables, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(observables, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    if #observables > 0 then result.observables = observables end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- files_red

local FILES_RED_COPY_MAPPINGS = {
    { source = "fuid",         target = "file.uid" },
    { source = "filename",     target = "file.name" },
    { source = "mime_type",    target = "file.mime_type" },
    { source = "total_bytes",  target = "file.size" },
    { source = "_system_name", target = "metadata.log_provider" },
    { source = "_path",        target = "metadata.log_name" },
}

local function processFilesRedEvents(event)
    local result = {}
    result.class_uid     = 6006
    result.class_name    = "File Hosting Activity"
    result.category_uid  = 6
    result.category_name = "Application Activity"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 600600
    result.type_name     = "File Hosting Activity: Unknown"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(FILES_RED_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- tx_hosts[] -> src_endpoint.ip (first element)
    local tx_hosts = getValue(event, "tx_hosts")
    if type(tx_hosts) == "table" and tx_hosts[1] ~= nil and tx_hosts[1] ~= "" then
        setNestedField(result, "src_endpoint.ip", tx_hosts[1])
    end
    mapped_keys["tx_hosts"] = true

    -- rx_hosts[] -> dst_endpoint.ip (first element, fallback tx_hosts)
    local rx_hosts = getValue(event, "rx_hosts")
    if type(rx_hosts) == "table" and rx_hosts[1] ~= nil and rx_hosts[1] ~= "" then
        setNestedField(result, "dst_endpoint.ip", rx_hosts[1])
    elseif type(tx_hosts) == "table" and tx_hosts[1] ~= nil and tx_hosts[1] ~= "" then
        setNestedField(result, "dst_endpoint.ip", tx_hosts[1])
    end
    mapped_keys["rx_hosts"] = true

    -- direction
    local src_ip = getNestedField(result, "src_endpoint.ip")
    local dst_ip = getNestedField(result, "dst_endpoint.ip")
    local dir_id, dir_name = computeDirection(src_ip, dst_ip)
    setNestedField(result, "connection_info.direction_id", dir_id)
    setNestedField(result, "connection_info.direction", dir_name)

    -- conn_uids[]
    local cuids = getValue(event, "conn_uids")
    if type(cuids) == "table" and cuids ~= nil and cuids ~= "" then
        setNestedField(result, "connection_info.uid", cuids)
    end
    mapped_keys["conn_uids"] = true

    -- missing_bytes -> traffic.bytes_missed, and (new) a severity that
    -- reflects a partially-captured file instead of a flat "Informational" always.
    local miss = tonumber(getValue(event, "missing_bytes"))
    if miss ~= nil then setNestedField(result, "traffic.bytes_missed", math.floor(miss)) end
    mapped_keys["missing_bytes"] = true
    if miss ~= nil and miss > 0 then
        setNestedField(result, "severity_id", 2)
        setNestedField(result, "severity", "Low")
    end

    -- file hashes
    buildFileHashes(event, result, FILE_HASH_FIELDS)
    mapped_keys["md5"] = true
    mapped_keys["sha1"] = true
    mapped_keys["sha256"] = true

    local is_orig = getValue(event, "is_orig")
    local direction_word = "transferred"
    if is_orig == true or is_orig == "true" then direction_word = "uploaded"
    elseif is_orig == false or is_orig == "false" then direction_word = "downloaded" end
    mapped_keys["is_orig"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)

    -- one-line summary
    local source_val = getValue(event, "source")
    setNestedField(result, "message",
        "File " .. direction_word .. " via " .. (source_val or "?") .. ": "
        .. (getNestedField(result, "file.mime_type") or "unknown"))

    -- observables
    local observables = {}
    addObservables(observables, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(observables, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    if #observables > 0 then result.observables = observables end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- ftp

local FTP_COPY_MAPPINGS = {
    { source = "uid",          target = "connection_info.uid" },
    { source = "command",      target = "command" },
    { source = "reply_msg",    target = "status_detail" },
    { source = "arg",          target = "name" },
    { source = "fuid",         target = "file.uid" },
    { source = "mime_type",    target = "file.mime_type" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processFtpEvents(event)
    local result = {}
    result.class_uid     = 4008
    result.class_name    = "FTP Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})
    setNestedField(result, "connection_info.protocol_name", "tcp")
    setNestedField(result, "connection_info.protocol_num", 6)
    setNestedField(result, "file.name", "Unknown")
    setNestedField(result, "file.type_id", 0)
    setNestedField(result, "file.type", "Unknown")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(FTP_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- activity_id from command
    local cmd = getValue(event, "command")
    local act_id = 0
    if cmd ~= nil and cmd ~= "" then
        act_id = FTP_CMD_MAP[tostring(cmd):upper()] or 99
        setNestedField(result, "activity_id", act_id)
        if act_id == 99 then
            setNestedField(result, "activity_name", tostring(cmd or "Other"))
        else
            setNestedField(result, "activity_name", FTP_ACT_CAPTIONS[act_id] or "Unknown")
        end
    end
    local type_uid_ftp = 4008 * 100 + act_id
    setNestedField(result, "type_uid", type_uid_ftp)
    setNestedField(result, "type_name", FTP_TYPE_CAPTIONS[type_uid_ftp] or ("FTP Activity: " .. (FTP_ACT_CAPTIONS[act_id] or "Other")))
    mapped_keys["command"] = true

    -- endpoints with fallback
    local orig_h = getValue(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then
        setNestedField(result, "src_endpoint.ip", orig_h)
    else
        local dc_orig = getValue(event, "data_channel.orig_h")
        if dc_orig ~= nil and dc_orig ~= "" then setNestedField(result, "src_endpoint.ip", dc_orig) end
    end
    mapped_keys["id.orig_h"] = true

    local resp_h = getValue(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then
        setNestedField(result, "dst_endpoint.ip", resp_h)
    else
        local dc_resp = getValue(event, "data_channel.resp_h")
        if dc_resp ~= nil and dc_resp ~= "" then setNestedField(result, "dst_endpoint.ip", dc_resp) end
    end
    mapped_keys["id.resp_h"] = true

    -- ports
    local orig_p = tonumber(getValue(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true
    local resp_p = tonumber(getValue(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction
    local src_ip_ftp = getNestedField(result, "src_endpoint.ip")
    local dst_ip_ftp = getNestedField(result, "dst_endpoint.ip")
    local dir_id_ftp, dir_name_ftp = computeDirection(src_ip_ftp, dst_ip_ftp)
    setNestedField(result, "connection_info.direction_id", dir_id_ftp)
    setNestedField(result, "connection_info.direction", dir_name_ftp)

    -- user -> dst_endpoint.owner.name
    local user_val = getValue(event, "user")
    if user_val ~= nil and not isPlaceholder(user_val) then
        setNestedField(result, "dst_endpoint.owner.name", user_val)
    end
    mapped_keys["user"] = true

    -- file_size -> file.size
    local fsz = tonumber(getValue(event, "file_size"))
    if fsz ~= nil then setNestedField(result, "file.size", math.floor(fsz)) end
    mapped_keys["file_size"] = true

    -- reply_code -> codes (single-element array), status_id, status, status_code
    local rc = tonumber(getValue(event, "reply_code"))
    if rc ~= nil then
        setNestedField(result, "codes", { rc })
        local rc_str = tostring(rc)
        setNestedField(result, "status_code", rc_str)
        local sid_ftp
        if rc >= 100 and rc <= 399 then sid_ftp = 1
        elseif rc >= 400 and rc <= 599 then sid_ftp = 2
        elseif rc ~= nil then sid_ftp = 99
        end
        if sid_ftp == nil then sid_ftp = 0 end
        setNestedField(result, "status_id", sid_ftp)
        if sid_ftp == 99 then setNestedField(result, "status", rc_str)
        else setNestedField(result, "status", STATUS_CAPTIONS[sid_ftp] or "Unknown") end
    else
        setNestedField(result, "status_id", 0)
        setNestedField(result, "status", "Unknown")
    end
    mapped_keys["reply_code"] = true

    -- reply_msg -> command_responses (single-element array)
    local rm = getValue(event, "reply_msg")
    if rm ~= nil and rm ~= "" then setNestedField(result, "command_responses", { rm }) end
    mapped_keys["reply_msg"] = true

    -- data_channel.passive -> type
    local passive = getValue(event, "data_channel.passive")
    if passive ~= nil and passive ~= "" then
        if passive == true or passive == "true" then
            setNestedField(result, "type", "passive")
        elseif passive == false or passive == "false" then
            setNestedField(result, "type", "active")
        end
    end
    mapped_keys["data_channel.passive"] = true

    -- data_channel.resp_p -> port
    local dc_resp_p = tonumber(getValue(event, "data_channel.resp_p"))
    if dc_resp_p ~= nil then setNestedField(result, "port", dc_resp_p) end
    mapped_keys["data_channel.resp_p"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- http
-- =========================================================

local HTTP_COPY_MAPPINGS = {
    { source = "uid",                  target = "connection_info.uid" },
    { source = "method",               target = "http_request.http_method" },
    { source = "host",                 target = "http_request.url.hostname" },
    { source = "user_agent",           target = "http_request.user_agent" },
    { source = "referrer",             target = "http_request.referrer" },
    { source = "version",              target = "http_request.version" },
    { source = "status_msg",           target = "http_response.message" },
    { source = "_path",                target = "metadata.log_name" },
    { source = "_system_name",         target = "metadata.log_provider" },
}

local function processHttpEvents(event)
    local result = {}
    result.class_uid     = 4002
    result.class_name    = "HTTP Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 400200
    result.type_name     = "HTTP Activity: Unknown"
    result.severity_id   = 1
    result.severity      = "Informational"
    result.status_id     = 0
    result.status        = "Unknown"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "http")
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(HTTP_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- id.orig_h -> src_endpoint.ip
    local orig_h_raw = getValue(event, "id.orig_h")
    local orig_h = (orig_h_raw ~= nil and not isPlaceholder(orig_h_raw)) and orig_h_raw or nil
    if orig_h ~= nil then
        setNestedField(result, "src_endpoint.ip", orig_h)
    end
    mapped_keys["id.orig_h"] = true

    -- id.orig_p -> src_endpoint.port
    local orig_p = tonumber(getValue(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    -- id.resp_h -> dst_endpoint.ip
    local resp_h_raw = getValue(event, "id.resp_h")
    local resp_h = (resp_h_raw ~= nil and not isPlaceholder(resp_h_raw)) and resp_h_raw or nil
    if resp_h ~= nil then
        setNestedField(result, "dst_endpoint.ip", resp_h)
    end
    mapped_keys["id.resp_h"] = true

    -- id.resp_p -> dst_endpoint.port
    local resp_p = tonumber(getValue(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- method -> activity_id, activity_name, type_uid, type_name
    setHttpActivity(result, getValue(event, "method"))

    -- direction
    local dir_id, dir_name = computeDirection(orig_h, resp_h)
    setNestedField(result, "connection_info.direction_id", dir_id)
    setNestedField(result, "connection_info.direction", dir_name)

    -- uri -> http_request.url.path
    local uri_val = getValue(event, "uri")
    if uri_val ~= nil and not isPlaceholder(uri_val) then
        setNestedField(result, "http_request.url.path", uri_val)
    end
    mapped_keys["uri"] = true

    -- request_body_len -> http_request.body_length and traffic.bytes_out
    local req_len = tonumber(getValue(event, "request_body_len"))
    if req_len ~= nil then
        setNestedField(result, "http_request.body_length", req_len)
        setNestedField(result, "traffic.bytes_out", req_len)
    end
    mapped_keys["request_body_len"] = true

    -- status_code -> http_response.code, plus (new) a status_id/status/severity
    -- that reflects the actual outcome instead of always "Unknown"/"Informational".
    local sc = tonumber(getValue(event, "status_code"))
    if sc ~= nil then setNestedField(result, "http_response.code", sc) end
    mapped_keys["status_code"] = true
    local http_sid, http_status, http_sev_id, http_sev = httpStatusFromCode(sc)
    setNestedField(result, "status_id", http_sid)
    setNestedField(result, "status", http_status)
    setNestedField(result, "severity_id", http_sev_id)
    setNestedField(result, "severity", http_sev)

    -- response_body_len -> http_response.body_length and traffic.bytes_in
    local resp_len = tonumber(getValue(event, "response_body_len"))
    if resp_len ~= nil then
        setNestedField(result, "http_response.body_length", resp_len)
        setNestedField(result, "traffic.bytes_in", resp_len)
    end
    mapped_keys["response_body_len"] = true

    -- resp_mime_types[] -> http_response.content_type
    local mime = getValue(event, "resp_mime_types")
    if mime ~= nil and mime ~= "" then setNestedField(result, "http_response.content_type", mime) end
    mapped_keys["resp_mime_types"] = true

    -- host -> dst_endpoint.hostname (in addition to http_request.url.hostname above)
    local host_val = getValue(event, "host")
    if host_val ~= nil and not isPlaceholder(host_val) then
        setNestedField(result, "dst_endpoint.hostname", host_val)
    end

    -- origin -> http_request.http_headers (single header object)
    local origin_val = getValue(event, "origin")
    local http_headers = {}
    if origin_val ~= nil and origin_val ~= "" then
        http_headers[#http_headers + 1] = { name = "Origin", value = tostring(origin_val) }
    end
    mapped_keys["origin"] = true

    -- client_headers[] -> http_request.http_headers appended after it
    -- (split on first colon); both rows target the same array, so they
    -- must be merged rather than one overwriting the other.
    local client_headers = getValue(event, "client_headers")
    if type(client_headers) == "table" and #client_headers > 0 then
        for _, h in ipairs(client_headers) do
            if type(h) == "string" then
                local colon = h:find(":", 1, true)
                if colon then
                    http_headers[#http_headers + 1] = { name = h:sub(1, colon - 1), value = h:sub(colon + 1):match("^%s*(.-)%s*$") }
                else
                    http_headers[#http_headers + 1] = { name = h, value = "" }
                end
            end
        end
    end
    mapped_keys["client_headers"] = true
    if #http_headers > 0 then setNestedField(result, "http_request.http_headers", http_headers) end

    -- server_headers[] -> http_response.http_headers (split on first colon)
    local server_headers = getValue(event, "server_headers")
    if type(server_headers) == "table" and #server_headers > 0 then
        local hdrs = {}
        for _, h in ipairs(server_headers) do
            if type(h) == "string" then
                local colon = h:find(":", 1, true)
                if colon then
                    hdrs[#hdrs + 1] = { name = h:sub(1, colon - 1), value = h:sub(colon + 1):match("^%s*(.-)%s*$") }
                else
                    hdrs[#hdrs + 1] = { name = h, value = "" }
                end
            end
        end
        if #hdrs > 0 then setNestedField(result, "http_response.http_headers", hdrs) end
    end
    mapped_keys["server_headers"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)

    -- one-line summary
    setNestedField(result, "message",
        (getValue(event, "method") or "?") .. " "
        .. (getNestedField(result, "http_request.url.hostname") or "?")
        .. (getNestedField(result, "http_request.url.path") or "")
        .. (sc ~= nil and (" -> " .. sc) or ""))

    -- observables
    local obs = {}
    addObservables(obs, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(obs, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    addObservables(obs, "http_request.url.hostname", "Hostname", 1, getNestedField(result, "http_request.url.hostname"))
    addObservables(obs, "http_request.user_agent", "HTTP User-Agent", 16, getNestedField(result, "http_request.user_agent"))
    addObservables(obs, "http_request.url.path", "URL String", 6, getNestedField(result, "http_request.url.path"))
    addObservables(obs, "http_request.referrer", "URL String", 6, getNestedField(result, "http_request.referrer"))
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- http2
-- =========================================================

local HTTP2_COPY_MAPPINGS = {
    { source = "uid",               target = "connection_info.uid" },
    { source = "host",              target = "http_request.url.hostname" },
    { source = "method",            target = "http_request.http_method" },
    { source = "user_agent",        target = "http_request.user_agent" },
    { source = "referrer",          target = "http_request.referrer" },
    { source = "version",           target = "http_request.version" },
    { source = "status_msg",        target = "http_response.message" },
    { source = "_path",             target = "metadata.log_name" },
    { source = "_system_name",         target = "metadata.log_provider" },
}

local function processHttp2Events(event)
    local result = {}
    result.class_uid     = 4002
    result.class_name    = "HTTP Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 400200
    result.type_name     = "HTTP Activity: Unknown"
    result.severity_id   = 1
    result.severity      = "Informational"
    result.status_id     = 0
    result.status        = "Unknown"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(HTTP2_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- id.orig_h -> src_endpoint.ip
    local orig_h = getValue(event, "id.orig_h")
    if orig_h ~= nil and not isPlaceholder(orig_h) then
        setNestedField(result, "src_endpoint.ip", orig_h)
    end
    mapped_keys["id.orig_h"] = true

    -- id.orig_p -> src_endpoint.port
    local orig_p = tonumber(getValue(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    -- id.resp_h -> dst_endpoint.ip
    local resp_h = getValue(event, "id.resp_h")
    if resp_h ~= nil and not isPlaceholder(resp_h) then
        setNestedField(result, "dst_endpoint.ip", resp_h)
    end
    mapped_keys["id.resp_h"] = true

    -- id.resp_p -> dst_endpoint.port
    local resp_p = tonumber(getValue(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- method -> activity_id, activity_name, type_uid, type_name
    setHttpActivity(result, getValue(event, "method"))

    -- uri -> http_request.url.path
    local uri_val = getValue(event, "uri")
    if uri_val ~= nil and not isPlaceholder(uri_val) then
        setNestedField(result, "http_request.url.path", uri_val)
    end
    mapped_keys["uri"] = true

    -- request_body_len -> http_request.body_length and traffic.bytes_out
    local req_len = tonumber(getValue(event, "request_body_len"))
    if req_len ~= nil then
        setNestedField(result, "http_request.body_length", req_len)
        setNestedField(result, "traffic.bytes_out", req_len)
    end
    mapped_keys["request_body_len"] = true

    -- status_code -> http_response.code, plus (new) a status_id/status/severity
    -- that reflects the actual outcome instead of always "Unknown"/"Informational".
    local sc = tonumber(getValue(event, "status_code"))
    if sc ~= nil then setNestedField(result, "http_response.code", sc) end
    mapped_keys["status_code"] = true
    local http_sid, http_status, http_sev_id, http_sev = httpStatusFromCode(sc)
    setNestedField(result, "status_id", http_sid)
    setNestedField(result, "status", http_status)
    setNestedField(result, "severity_id", http_sev_id)
    setNestedField(result, "severity", http_sev)

    -- response_body_len -> http_response.body_length and traffic.bytes_in
    local resp_len = tonumber(getValue(event, "response_body_len"))
    if resp_len ~= nil then
        setNestedField(result, "http_response.body_length", resp_len)
        setNestedField(result, "traffic.bytes_in", resp_len)
    end
    mapped_keys["response_body_len"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- observables
    local obs = {}
    addObservables(obs, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(obs, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    addObservables(obs, "http_request.url.hostname", "Hostname", 1, getNestedField(result, "http_request.url.hostname"))
    addObservables(obs, "http_request.url.path", "URL String", 6, getNestedField(result, "http_request.url.path"))
    addObservables(obs, "http_request.user_agent", "HTTP User-Agent", 16, getNestedField(result, "http_request.user_agent"))
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- http_agg
-- =========================================================

local HTTP_AGG_COPY_MAPPINGS = {
    { source = "_path",             target = "metadata.log_name" },
    { source = "host",              target = "http_request.url.hostname" },
    { source = "user_agent",        target = "http_request.user_agent" },
    { source = "referrer",          target = "http_request.referrer" },
    { source = "version",           target = "http_request.version" },
    { source = "status_msg",        target = "http_response.message" },
    { source = "_system_name",      target = "metadata.log_provider" },
}

local function processHttpAggEvents(event)
    local result = {}
    result.class_uid     = 4002
    result.class_name    = "HTTP Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local ts_last = convertToMilliseconds(tostring(getValue(event, "ts_last") or ""))
    if ts_last ~= nil then setNestedField(result, "end_time", ts_last) end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(HTTP_AGG_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["ts_last"] = true
    mapped_keys["_write_ts"] = true

    -- method -> http_request.http_method + activity_id + type_uid + type_name
    local method_raw = getValue(event, "method")
    local method_upper
    do
        local _m = method_raw
        if type(_m) == "table" then _m = nil end
        if type(_m) ~= "string" then _m = tostring(_m or "") end
        method_upper = _m:upper()
    end
    local act_id, act_name
    if method_upper == "" then
        act_id, act_name = 0, "Unknown"
    else
        act_id = HTTP_METHOD_TYPE_MAP[method_upper]
        if act_id == nil then
            act_id = 99
            act_name = tostring(method_raw or method_upper)
        else
            act_name = method_upper:sub(1,1) .. method_upper:sub(2):lower()
        end
    end
    setNestedField(result, "activity_id", act_id)
    setNestedField(result, "activity_name", act_name)
    local type_uid_val = 4002 * 100 + act_id
    setNestedField(result, "type_uid", type_uid_val)
    setNestedField(result, "type_name", HTTP_AGG_TYPE_CAPTIONS[type_uid_val] or ("HTTP Activity: " .. act_name))
    if method_raw ~= nil and method_raw ~= "" then
        setNestedField(result, "http_request.http_method", method_raw)
    end
    mapped_keys["method"] = true

    -- id.orig_h / id.resp_h
    local orig_h = getValue(event, "id.orig_h")
    if orig_h ~= nil and not isPlaceholder(orig_h) then
        setNestedField(result, "src_endpoint.ip", orig_h)
    end
    mapped_keys["id.orig_h"] = true

    local resp_h = getValue(event, "id.resp_h")
    if resp_h ~= nil and not isPlaceholder(resp_h) then
        setNestedField(result, "dst_endpoint.ip", resp_h)
    end
    mapped_keys["id.resp_h"] = true

    -- uri -> http_request.url.path
    local uri_val = getValue(event, "uri")
    if uri_val ~= nil and not isPlaceholder(uri_val) then
        setNestedField(result, "http_request.url.path", uri_val)
    end
    mapped_keys["uri"] = true

    -- request_body_len -> http_request.body_length and traffic.bytes_out
    local req_len = tonumber(getValue(event, "request_body_len"))
    if req_len ~= nil then
        setNestedField(result, "http_request.body_length", req_len)
        setNestedField(result, "traffic.bytes_out", req_len)
    end
    mapped_keys["request_body_len"] = true

    -- status_code -> http_response.code, plus (new) a status_id/status/severity
    -- that reflects the actual outcome instead of always "Unknown"/"Informational".
    local sc = tonumber(getValue(event, "status_code"))
    if sc ~= nil then setNestedField(result, "http_response.code", sc) end
    mapped_keys["status_code"] = true
    local http_sid, http_status, http_sev_id, http_sev = httpStatusFromCode(sc)
    setNestedField(result, "status_id", http_sid)
    setNestedField(result, "status", http_status)
    setNestedField(result, "severity_id", http_sev_id)
    setNestedField(result, "severity", http_sev)

    -- response_body_len -> http_response.body_length and traffic.bytes_in
    local resp_len = tonumber(getValue(event, "response_body_len"))
    if resp_len ~= nil then
        setNestedField(result, "http_response.body_length", resp_len)
        setNestedField(result, "traffic.bytes_in", resp_len)
    end
    mapped_keys["response_body_len"] = true

    -- resp_mime_types[] -> http_response.content_type
    local mime = getValue(event, "resp_mime_types")
    if mime ~= nil and mime ~= "" then setNestedField(result, "http_response.content_type", mime) end
    mapped_keys["resp_mime_types"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)

    -- one-line summary
    setNestedField(result, "message",
        (method_raw or "?") .. " "
        .. (getNestedField(result, "dst_endpoint.domain") or getNestedField(result, "http_request.url.hostname") or "?")
        .. (getNestedField(result, "http_request.url.path") or "")
        .. (sc ~= nil and (" -> " .. sc) or ""))

    -- observables
    local obs = {}
    addObservables(obs, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(obs, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    addObservables(obs, "http_request.url.path", "URL String", 6, getNestedField(result, "http_request.url.path"))
    addObservables(obs, "http_request.url.hostname", "Hostname", 1, getNestedField(result, "http_request.url.hostname"))
    addObservables(obs, "dst_endpoint.domain", "Hostname", 1, getNestedField(result, "dst_endpoint.domain"))
    addObservables(obs, "http_request.user_agent", "HTTP User-Agent", 16, getNestedField(result, "http_request.user_agent"))
    addObservables(obs, "http_request.referrer", "URL String", 6, getNestedField(result, "http_request.referrer"))
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- http_red
-- =========================================================

local HTTP_RED_COPY_MAPPINGS = {
    { source = "uid",               target = "connection_info.uid" },
    { source = "host",              target = "http_request.url.hostname" },
    { source = "user_agent",        target = "http_request.user_agent" },
    { source = "referrer",          target = "http_request.referrer" },
    { source = "version",           target = "http_request.version" },
    { source = "status_msg",        target = "http_response.message" },
    { source = "_path",             target = "metadata.log_name" },
    { source = "_system_name",      target = "metadata.log_provider" },
}

local function processHttpRedEvents(event)
    local result = {}
    result.class_uid     = 4002
    result.class_name    = "HTTP Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 400200
    result.type_name     = "HTTP Activity: Unknown"
    result.severity_id   = 1
    result.severity      = "Informational"
    result.status_id     = 0
    result.status        = "Unknown"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "http_red")
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(HTTP_RED_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- method -> http_request.http_method + activity_id + type_uid + type_name
    local method_raw = getValue(event, "method")
    if method_raw ~= nil and method_raw ~= "" then
        setNestedField(result, "http_request.http_method", method_raw)
        local method_s = method_raw
        if type(method_s) == "table" then method_s = nil end
        if type(method_s) ~= "string" then method_s = tostring(method_s or "") end
        local method_upper = method_s:upper()
        local act_id = HTTP_METHOD_TYPE_MAP[method_upper]
        local act_name
        if act_id == nil then
            act_id = 99
            act_name = method_s
        else
            act_name = method_upper:sub(1,1) .. method_upper:sub(2):lower()
        end
        result.activity_id = act_id
        result.activity_name = act_name
        local type_uid_val = 4002 * 100 + act_id
        result.type_uid  = type_uid_val
        result.type_name = HTTP_AGG_TYPE_CAPTIONS[type_uid_val] or ("HTTP Activity: " .. act_name)
    end
    mapped_keys["method"] = true

    local orig_h = getValue(event, "id.orig_h")
    if orig_h ~= nil and not isPlaceholder(orig_h) then
        setNestedField(result, "src_endpoint.ip", orig_h)
    end
    mapped_keys["id.orig_h"] = true

    -- id.orig_p -> src_endpoint.port
    local orig_p = tonumber(getValue(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    -- id.resp_h -> dst_endpoint.ip
    local resp_h = getValue(event, "id.resp_h")
    if resp_h ~= nil and not isPlaceholder(resp_h) then
        setNestedField(result, "dst_endpoint.ip", resp_h)
    end
    mapped_keys["id.resp_h"] = true

    -- id.resp_p -> dst_endpoint.port
    local resp_p = tonumber(getValue(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction
    local dir_id, dir_name = computeDirection(orig_h, resp_h)
    setNestedField(result, "connection_info.direction_id", dir_id)
    setNestedField(result, "connection_info.direction", dir_name)

    -- uri -> http_request.url.path
    local uri_val = getValue(event, "uri")
    if uri_val ~= nil and not isPlaceholder(uri_val) then
        setNestedField(result, "http_request.url.path", uri_val)
    end
    mapped_keys["uri"] = true

    -- request_body_len -> http_request.body_length and traffic.bytes_out
    local req_len = tonumber(getValue(event, "request_body_len"))
    if req_len ~= nil then
        setNestedField(result, "http_request.body_length", req_len)
        setNestedField(result, "traffic.bytes_out", req_len)
    end
    mapped_keys["request_body_len"] = true

    -- status_code -> http_response.code, plus (new) a status_id/status/severity
    -- that reflects the actual outcome instead of always "Unknown"/"Informational".
    local sc = tonumber(getValue(event, "status_code"))
    if sc ~= nil then setNestedField(result, "http_response.code", sc) end
    mapped_keys["status_code"] = true
    local http_sid, http_status, http_sev_id, http_sev = httpStatusFromCode(sc)
    setNestedField(result, "status_id", http_sid)
    setNestedField(result, "status", http_status)
    setNestedField(result, "severity_id", http_sev_id)
    setNestedField(result, "severity", http_sev)

    -- response_body_len -> http_response.body_length and traffic.bytes_in
    local resp_len = tonumber(getValue(event, "response_body_len"))
    if resp_len ~= nil then
        setNestedField(result, "http_response.body_length", resp_len)
        setNestedField(result, "traffic.bytes_in", resp_len)
    end
    mapped_keys["response_body_len"] = true

    -- resp_mime_types[] -> http_response.content_type
    local mime = getValue(event, "resp_mime_types")
    if mime ~= nil and mime ~= "" then setNestedField(result, "http_response.content_type", mime) end
    mapped_keys["resp_mime_types"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)

    -- one-line summary
    setNestedField(result, "message",
        (method_raw or "?") .. " "
        .. (getNestedField(result, "http_request.url.hostname") or "?")
        .. (getNestedField(result, "http_request.url.path") or "")
        .. (sc ~= nil and (" -> " .. sc) or ""))

    -- observables
    local obs = {}
    addObservables(obs, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(obs, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    addObservables(obs, "http_request.url.hostname", "Hostname", 1, getNestedField(result, "http_request.url.hostname"))
    addObservables(obs, "http_request.url.path", "URL String", 6, getNestedField(result, "http_request.url.path"))
    addObservables(obs, "http_request.user_agent", "HTTP User-Agent", 16, getNestedField(result, "http_request.user_agent"))
    addObservables(obs, "http_request.referrer", "URL String", 6, getNestedField(result, "http_request.referrer"))
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end


-- =========================================================
-- intel
-- =========================================================

local INTEL_COPY_MAPPINGS = {
    { source = "uid",           target = "connection_info.uid" },
    { source = "_path",         target = "metadata.log_name" },
    { source = "_system_name",  target = "metadata.log_provider" },
}

local INTEL_TYPE_CAPTION_MAP = {
    [0]="Unknown",[1]="IP Address",[2]="Domain",[3]="Hostname",[4]="Hash",
    [5]="URL",[6]="User Agent",[7]="Digital Certificate",[8]="Email",
    [9]="Email Address",[10]="Vulnerability",[11]="File",[12]="Registry Key",
    [13]="Registry Value",[14]="Command Line",[99]="Other"
}

local function processIntelEvents(event)
    local result = {}
    result.class_uid          = 2004
    result.class_name         = "Detection Finding"
    result.category_uid       = 2
    result.category_name      = "Findings"
    result.activity_id        = 1
    result.activity_name      = "Create"
    result.type_uid           = 200401
    result.type_name          = "Detection Finding: Create"
    result.severity_id        = 0
    result.severity           = "Unknown"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "intel")
    setNestedField(result, "metadata.profiles", { "osint" })
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "resources[0].name", "Unknown")
    setNestedField(result, "attack_surface_ids", { 2 })

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(INTEL_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- seen.indicator -> osint[0].value and finding_info.title ("Intel match: <indicator>")
    local indicator = getNestedField(event, "seen.indicator")
    if indicator ~= nil and indicator ~= "" then
        setNestedField(result, "osint[0].value", indicator)
        setNestedField(result, "finding_info.title", "Intel match: " .. tostring(indicator))
    end
    mapped_keys["seen.indicator"] = true

    -- seen.indicator_type -> osint[0].type_id + osint[0].type
    local ind_type_raw = getNestedField(event, "seen.indicator_type")
    local ind_type_id = 0
    if ind_type_raw ~= nil and ind_type_raw ~= "" then
        ind_type_id = INTEL_INDICATOR_TYPE_MAP[tostring(ind_type_raw):upper()] or 99
    else
        -- fallback: first element of matched[]
        local matched = getValue(event, "matched")
        if type(matched) == "table" and #matched > 0 then
            ind_type_id = INTEL_INDICATOR_TYPE_MAP[tostring(matched[1]):upper()] or 99
        end
    end
    setNestedField(result, "osint[0].type_id", ind_type_id)
    setNestedField(result, "osint[0].type", INTEL_TYPE_CAPTION_MAP[ind_type_id] or "Other")
    mapped_keys["seen.indicator_type"] = true

    -- sources[] -> osint[0].vendor_name (first element)
    local sources = getValue(event, "sources")
    if type(sources) == "table" and #sources > 0 and tostring(sources[1]) ~= "" then
        setNestedField(result, "osint[0].vendor_name", tostring(sources[1]))
    end

    -- sources[] -> JSON string at unmapped.sources
    addArrayFieldUnmapped(event, result, mapped_keys, "sources")

    -- confidence[] -> confidence_score (first element as int)
    local confidence = getValue(event, "confidence")
    if type(confidence) == "table" and #confidence > 0 then
        local cv = tonumber(confidence[1])
        if cv ~= nil then setNestedField(result, "confidence_score", cv) end
    end
    mapped_keys["confidence"] = true

    -- threat_score[] -> risk_score (first element as int)
    local threat_score = getValue(event, "threat_score")
    if type(threat_score) == "table" and #threat_score > 0 then
        local tv = tonumber(threat_score[1])
        if tv ~= nil then setNestedField(result, "risk_score", tv) end
    end
    mapped_keys["threat_score"] = true

    -- campaigns[] -> osint[0].campaign.name (first element, guard empty)
    local campaigns = getValue(event, "campaigns")
    if type(campaigns) == "table" and #campaigns > 0 then
        local cv = tostring(campaigns[1] or "")
        if cv ~= "" and not isPlaceholder(cv) then
            setNestedField(result, "osint[0].campaign.name", cv)
        end
    end
    mapped_keys["campaigns"] = true

    -- associated[] -> osint[0].intrusion_sets (array)
    local associated = getValue(event, "associated")
    if type(associated) == "table" and #associated > 0 then
        setNestedField(result, "osint[0].intrusion_sets", associated)
    end
    mapped_keys["associated"] = true

    -- desc[] -> osint[0].desc (first element)
    local desc = getValue(event, "desc")
    if type(desc) == "table" and #desc > 0 then
        local dv = tostring(desc[1] or "")
        if dv ~= "" then setNestedField(result, "osint[0].desc", dv) end
    end
    mapped_keys["desc"] = true

    -- category[] -> osint[0].labels (array)
    local category = getValue(event, "category")
    if type(category) == "table" and #category > 0 then
        setNestedField(result, "osint[0].labels", category)
    end
    mapped_keys["category"] = true

    -- url[] -> osint[0].src_url (first element)
    local url = getValue(event, "url")
    if type(url) == "table" and #url > 0 then
        local uv = tostring(url[1] or "")
        if uv ~= "" then setNestedField(result, "osint[0].src_url", uv) end
    end
    mapped_keys["url"] = true

    -- reports[] -> osint[0].references (array)
    local reports = getValue(event, "reports")
    if type(reports) == "table" and #reports > 0 then
        setNestedField(result, "osint[0].references", reports)
    end
    mapped_keys["reports"] = true

    -- id.orig_h -> src_endpoint.ip / evidences[0].src_endpoint.ip
    local orig_h = getNestedField(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then
        setNestedField(result, "src_endpoint.ip", orig_h)
        setNestedField(result, "evidences[0].src_endpoint.ip", orig_h)
    end
    mapped_keys["id.orig_h"] = true

    local orig_p = tonumber(getNestedField(event, "id.orig_p"))
    if orig_p ~= nil then
        setNestedField(result, "src_endpoint.port", orig_p)
        setNestedField(result, "evidences[0].src_endpoint.port", orig_p)
    end
    mapped_keys["id.orig_p"] = true

    local resp_h = getNestedField(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then
        setNestedField(result, "dst_endpoint.ip", resp_h)
        setNestedField(result, "evidences[0].dst_endpoint.ip", resp_h)
    end
    mapped_keys["id.resp_h"] = true

    local resp_p = tonumber(getNestedField(event, "id.resp_p"))
    if resp_p ~= nil then
        setNestedField(result, "dst_endpoint.port", resp_p)
        setNestedField(result, "evidences[0].dst_endpoint.port", resp_p)
    end
    mapped_keys["id.resp_p"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- observables
    local obs = {}
    addObservables(obs, "evidences[0].src_endpoint.ip", "IP Address", 2, orig_h)
    addObservables(obs, "evidences[0].dst_endpoint.ip", "IP Address", 2, resp_h)
    addObservables(obs, "finding_info.title", "Other", 99, getNestedField(result, "finding_info.title"))
    addObservables(obs, "osint[0].value", "Other", 99, indicator)
    local src_url_obs = getNestedField(result, "osint[0].src_url")
    addObservables(obs, "osint[0].src_url", "URL String", 6, src_url_obs)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end


-- =========================================================
-- kerberos
-- =========================================================

local KERB_ENC_ALG_CAPTIONS = {
    [0]="Unknown",[1]="DES",[2]="TripleDES",[3]="AES",[4]="RSA",[5]="ECC",[6]="SM2",[99]="Other"
}

-- Leading token of a Kerberos etype/cipher string (e.g. "aes256" from
-- "aes256-cts-hmac-sha1-96")
local KERB_CIPHER_PREFIX_ALG_ID = {
    { prefix = "des3", alg_id = 2 }, -- TripleDES
    { prefix = "des",  alg_id = 1 }, -- DES
    { prefix = "aes",  alg_id = 3 }, -- AES
    { prefix = "rsa",  alg_id = 4 },
    { prefix = "ecc",  alg_id = 5 },
    { prefix = "sm2",  alg_id = 6 },
}

-- Classifies a raw Kerberos cipher string into an OCSF algorithm_id by
-- matching the leading token
local function kerbCipherAlgId(cipher)
    if type(cipher) ~= "string" or cipher == "" then return 0 end
    local first_word = cipher:lower():match("^[^%-]+") or cipher:lower()
    for _, entry in ipairs(KERB_CIPHER_PREFIX_ALG_ID) do
        if first_word:sub(1, #entry.prefix) == entry.prefix then
            return entry.alg_id
        end
    end
    return 99
end

-- Weak/legacy Kerberos ciphers that should raise the event's severity.
local KERB_WEAK_CIPHER = {
    ["rc4-hmac"]=true, ["des-cbc-crc"]=true, ["des-cbc-md5"]=true, ["arcfour-hmac"]=true,
}
-- Specific KDC error codes that indicate a more serious problem than a
-- routine failed logon (e.g. integrity failures, revoked accounts).
local KERB_ERROR_SEVERITY = {
    ["KRB5KRB_AP_ERR_BAD_INTEGRITY"] = 4,
    ["KRB5KDC_ERR_PREAUTH_FAILED"]   = 3,
    ["KRB5KDC_ERR_CLIENT_REVOKED"]   = 3,
}
local KERB_SEVERITY_CAPTIONS = { [1]="Informational", [2]="Low", [3]="Medium", [4]="High" }

local KERB_COPY_MAPPINGS = {
    { source = "error_msg",           target = "status_detail" },
    { source = "uid",                 target = "metadata.uid" },
    { source = "_path",               target = "metadata.log_name" },
    { source = "_system_name",        target = "metadata.log_provider" },
    { source = "client_cert_fuid",    target = "certificate.uid" },
    { source = "client_cert_subject", target = "certificate.subject" },
}

local function processKerberosEvents(event)
    local result = {}
    result.class_uid       = 3002
    result.class_name      = "Authentication"
    result.category_uid    = 3
    result.category_name   = "Identity & Access Management"
    result.severity_id     = 1
    result.severity        = "Informational"
    result.auth_protocol_id = 2
    result.auth_protocol   = "Kerberos"
    setNestedField(result, "certificate.issuer", "Unknown")
    setNestedField(result, "certificate.serial_number", "Unknown")
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(KERB_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- request_type -> activity_id, type_uid, type_name
    local req_type = getValue(event, "request_type")
    local act_id = 0
    if req_type ~= nil and req_type ~= "" then
        act_id = KERB_REQUEST_TYPE_MAP[tostring(req_type):upper()] or 99
    else
        -- fallback: service starts with "krbtgt/" -> 3 (Authentication Ticket)
        local svc = getValue(event, "service")
        if type(svc) == "string" and svc:sub(1, 7) == "krbtgt/" then
            act_id = 3
        end
    end
    setNestedField(result, "activity_id", act_id)
    setNestedField(result, "activity_name", (act_id == 99 and tostring(req_type or "Other")) or (KERB_ACT_CAPTIONS[act_id] or "Unknown"))
    local type_uid_k = 3002 * 100 + act_id
    setNestedField(result, "type_uid", type_uid_k)
    setNestedField(result, "type_name", "Authentication: " .. (KERB_ACT_CAPTIONS[act_id] or "Unknown"))
    mapped_keys["request_type"] = true

    -- success -> status_id + status
    local success_raw = getValue(event, "success")
    local sid_k = 0
    if success_raw == true or success_raw == "true" then
        sid_k = 1
    elseif success_raw == false or success_raw == "false" then
        sid_k = 2
    elseif success_raw ~= nil and success_raw ~= "" then
        sid_k = 99
    end
    setNestedField(result, "status_id", sid_k)
    if sid_k == 99 then setNestedField(result, "status", tostring(success_raw))
    else setNestedField(result, "status", STATUS_CAPTIONS[sid_k] or "Unknown") end
    mapped_keys["success"] = true

    -- A severity that reflects a failed logon (and, further, specific known
    -- error codes or a weak/legacy cipher) instead of a flat "Informational"
    -- always.
    local kerb_sev = 1
    if sid_k == 2 then
        kerb_sev = 2
        local error_msg = getValue(event, "error_msg")
        if type(error_msg) == "string" then
            kerb_sev = math.max(kerb_sev, KERB_ERROR_SEVERITY[error_msg] or 2)
        end
    end

    -- client -> user.name (fallback: CN from client_cert_subject)
    local client = getValue(event, "client")
    local user_name = nil
    if client ~= nil and client ~= "" then
        user_name = client
    else
        local cert_subj = getValue(event, "client_cert_subject")
        if type(cert_subj) == "string" then
            local cn = cert_subj:match("CN=([^,/]+)")
            if cn then user_name = cn end
        end
    end
    if user_name ~= nil then
        setNestedField(result, "user.name", user_name)
    else
        setNestedField(result, "user.name", "Unknown")
    end
    mapped_keys["client"] = true

    -- client -> user.domain (last segment after '/')
    if type(client) == "string" and client ~= "" then
        local parts = {}
        for p in client:gmatch("[^/]+") do parts[#parts + 1] = p end
        if #parts > 0 then setNestedField(result, "user.domain", parts[#parts]) end
    end

    -- service -> service.name
    local svc_val = getValue(event, "service")
    if svc_val ~= nil and svc_val ~= "" then
        setNestedField(result, "service.name", svc_val)
    end
    mapped_keys["service"] = true

    -- endpoints
    local orig_h = getNestedField(event, "id.orig_h")
    if orig_h ~= nil and not isPlaceholder(orig_h) then
        setNestedField(result, "src_endpoint.ip", orig_h)
    end
    mapped_keys["id.orig_h"] = true

    local orig_p = tonumber(getNestedField(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    local resp_h = getNestedField(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then setNestedField(result, "dst_endpoint.ip", resp_h) end
    mapped_keys["id.resp_h"] = true

    local resp_p = tonumber(getNestedField(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- cipher -> authentication_token.encryption_details
    local cipher = getValue(event, "cipher")
    local alg_id = kerbCipherAlgId(cipher)
    setNestedField(result, "authentication_token.encryption_details.algorithm_id", alg_id)
    local enc_alg = alg_id == 99 and tostring(cipher) or (KERB_ENC_ALG_CAPTIONS[alg_id] or "Unknown")
    setNestedField(result, "authentication_token.encryption_details.algorithm", enc_alg)
    mapped_keys["cipher"] = true
    if type(cipher) == "string" and KERB_WEAK_CIPHER[cipher:lower()] then
        kerb_sev = math.max(kerb_sev, 3)
    end
    setNestedField(result, "severity_id", kerb_sev)
    setNestedField(result, "severity", KERB_SEVERITY_CAPTIONS[kerb_sev] or "Informational")

    -- renewable -> authentication_token.is_renewable
    local renewable = getValue(event, "renewable")
    if renewable ~= nil and renewable ~= "" then
        local rv = (renewable == true or renewable == "true")
        setNestedField(result, "authentication_token.is_renewable", rv)
    end
    mapped_keys["renewable"] = true

    -- from -> authentication_token.created_time
    local from_ts = convertToMilliseconds(tostring(getValue(event, "from") or ""))
    if from_ts ~= nil then setNestedField(result, "authentication_token.created_time", from_ts) end
    mapped_keys["from"] = true

    -- till -> authentication_token.expiration_time
    local till_ts = convertToMilliseconds(tostring(getValue(event, "till") or ""))
    if till_ts ~= nil then setNestedField(result, "authentication_token.expiration_time", till_ts) end
    mapped_keys["till"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)

    -- one-line summary
    setNestedField(result, "message",
        "Kerberos " .. (tostring(req_type or "")) .. " " .. (user_name or "")
        .. (sid_k == 1 and " [SUCCESS]" or sid_k == 2 and " [FAILURE]" or ""))

    -- observables
    local obs = {}
    addObservables(obs, "src_endpoint.ip", "IP Address", 2, orig_h)
    addObservables(obs, "dst_endpoint.ip", "IP Address", 2, resp_h)
    addObservables(obs, "user.name", "User Name", 4, client)
    addObservables(obs, "service.name", "Other", 99, svc_val)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end


-- =========================================================
-- notice
-- =========================================================

local NOTICE_DISP_CAPTION_MAP = {
    [0]="Unknown",[1]="Allowed",[2]="Blocked",[3]="Quarantined",[4]="Isolated",
    [5]="Deleted",[6]="Dropped",[7]="Custom Action",[8]="Approved",[9]="Restored",
    [10]="Exonerated",[11]="Corrected",[12]="Partially Corrected",[13]="Uncorrected",
    [14]="Delayed",[15]="Detected",[16]="No Action",[17]="Logged",[18]="Tagged",
    [19]="Alert",[20]="Count",[21]="Reset",[22]="Captcha",[23]="Challenge",
    [24]="Access Revoked",[25]="Rejected",[26]="Unauthorized",[27]="Error",[99]="Other"
}

local NOTICE_COPY_MAPPINGS = {
    { source = "msg",         target = "message" },
    { source = "uid",         target = "connection_info.uid" },
    { source = "sub",         target = "finding_info.desc" },
    { source = "proto",       target = "evidences[0].connection_info.protocol_name" },
    { source = "_path",       target = "metadata.log_name" },
    { source = "_system_name",target = "metadata.log_provider" },
}

local function processNoticeEvents(event)
    local result = {}
    result.class_uid     = 2004
    result.class_name    = "Detection Finding"
    result.category_uid  = 2
    result.category_name = "Findings"
    result.activity_id   = 1
    result.activity_name = "Create"
    result.type_uid      = 200401
    result.type_name     = "Detection Finding: Create"
    result.action_id     = 3
    result.action        = "Observed"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.profiles", { "security_control" })
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(NOTICE_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- severity.name -> severity_id + severity
    local sev_name_raw = getNestedField(event, "severity.name")
    local sev_id = 0
    if sev_name_raw ~= nil and sev_name_raw ~= "" then
        local sev_s = sev_name_raw
        if type(sev_s) == "table" then sev_s = nil end
        if type(sev_s) ~= "string" then sev_s = tostring(sev_s or "") end
        -- strip Zeek's " (default)" suffix, e.g. "informational (default)"
        local sev_upper = sev_s:upper()
        local sev_key = sev_upper:match("^%s*(%a+)") or sev_upper
        sev_id = NOTICE_SEV_MAP[sev_key] or 99
    else
        -- fallback: severity.level, still preserved as-is under unmapped.severity.level
        local sev_level = tonumber(getNestedField(event, "severity.level"))
        if sev_level ~= nil then sev_id = NOTICE_SEV_LEVEL_MAP[sev_level] or 99 end
    end
    local SEV_NAMES = {"Unknown","Informational","Low","Medium","High","Critical","Fatal"}
    setNestedField(result, "severity_id", sev_id)
    if sev_id == 99 then setNestedField(result, "severity", tostring(sev_name_raw or "Other"))
    else setNestedField(result, "severity", SEV_NAMES[sev_id + 1] or "Unknown") end
    -- mapped_keys["severity.name"] = true -> Here, we are not marking it as true because we need it for dashboard visualization

    -- peer_descr -> metadata.reporter.uid
    local peer = getValue(event, "peer_descr")
    if peer ~= nil and not isPlaceholder(peer) then
        setNestedField(result, "metadata.reporter.uid", peer)
    end
    mapped_keys["peer_descr"] = true

    -- suppress_for -> duration (seconds to milliseconds)
    local sup = tonumber(getValue(event, "suppress_for"))
    if sup ~= nil then setNestedField(result, "duration", math.floor(sup * 1000)) end
    mapped_keys["suppress_for"] = true

    -- id.orig_h -> evidences[0].src_endpoint.ip
    local orig_h = getNestedField(event, "id.orig_h")
    local src_ip = nil
    if orig_h ~= nil and orig_h ~= "" then
        src_ip = orig_h
    else
        local src_field = getValue(event, "src")
        if src_field ~= nil and src_field ~= "" then src_ip = src_field end
    end
    if src_ip ~= nil then setNestedField(result, "evidences[0].src_endpoint.ip", src_ip) end
    mapped_keys["id.orig_h"] = true

    local orig_p = tonumber(getNestedField(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "evidences[0].src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    -- id.resp_h -> evidences[0].dst_endpoint.ip
    local resp_h = getNestedField(event, "id.resp_h")
    local dst_ip = nil
    if resp_h ~= nil and resp_h ~= "" then
        dst_ip = resp_h
    else
        local dst_field = getValue(event, "dst")
        if dst_field ~= nil and dst_field ~= "" then dst_ip = dst_field end
    end
    if dst_ip ~= nil then setNestedField(result, "evidences[0].dst_endpoint.ip", dst_ip) end
    mapped_keys["id.resp_h"] = true

    local resp_p = tonumber(getNestedField(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "evidences[0].dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction for evidences[0].connection_info
    local edir_id, edir_name = computeDirection(src_ip, dst_ip)
    setNestedField(result, "evidences[0].connection_info.direction_id", edir_id)
    setNestedField(result, "evidences[0].connection_info.direction", edir_name)

    -- actions[] -> finding_info.types + disposition_id + disposition
    local actions = getValue(event, "actions")
    if type(actions) == "table" and #actions > 0 then
        setNestedField(result, "finding_info.types", actions)
    end
    mapped_keys["actions"] = true

    -- file evidence fields (evidences[0].file object, and its required
    -- name/type_id/type stubs, only added when file evidence actually exists)
    local file_desc = getValue(event, "file_desc")
    local file_mime = getValue(event, "file_mime_type")
    local fuid = getValue(event, "fuid")
    if (fuid ~= nil and fuid ~= "") or (file_mime ~= nil and file_mime ~= "") then
        if file_desc ~= nil and file_desc ~= "" then setNestedField(result, "evidences[0].file.desc", file_desc) end
        if file_mime ~= nil and file_mime ~= "" then setNestedField(result, "evidences[0].file.mime_type", file_mime) end
        if fuid ~= nil and fuid ~= "" then setNestedField(result, "evidences[0].file.uid", fuid) end
    end
    mapped_keys["file_desc"] = true
    mapped_keys["file_mime_type"] = true
    mapped_keys["fuid"] = true

    -- orig_vulnerable_host -> resources[0]
    local ovh_hostname = getNestedField(event, "orig_vulnerable_host.hostname")
    if ovh_hostname ~= nil and not isPlaceholder(ovh_hostname) then
        setNestedField(result, "resources[0].name", ovh_hostname)
    end
    local ovh_uid = getNestedField(event, "orig_vulnerable_host.host_uid")
    if ovh_uid ~= nil and not isPlaceholder(ovh_uid) then
        setNestedField(result, "resources[0].uid", ovh_uid)
    end
    local ovh_crit = getNestedField(event, "orig_vulnerable_host.criticality")
    if ovh_crit ~= nil and ovh_crit ~= "" then setNestedField(result, "resources[0].criticality", ovh_crit) end
    local ovh_cve = getNestedField(event, "orig_vulnerable_host.cve")
    if ovh_cve ~= nil and ovh_cve ~= "" then setNestedField(result, "vulnerabilities[0].cve.uid", ovh_cve) end
    mapped_keys["orig_vulnerable_host.hostname"] = true
    mapped_keys["orig_vulnerable_host.host_uid"] = true
    mapped_keys["orig_vulnerable_host.criticality"] = true
    mapped_keys["orig_vulnerable_host.cve"] = true

    -- resp_vulnerable_host -> resources[1]
    local rvh_hostname = getNestedField(event, "resp_vulnerable_host.hostname")
    if rvh_hostname ~= nil and rvh_hostname ~= "" then
        setNestedField(result, "resources[1].name", rvh_hostname)
    end
    local rvh_uid = getNestedField(event, "resp_vulnerable_host.host_uid")
    if rvh_uid ~= nil and rvh_uid ~= "" then setNestedField(result, "resources[1].uid", rvh_uid) end
    local rvh_crit = getNestedField(event, "resp_vulnerable_host.criticality")
    if rvh_crit ~= nil and rvh_crit ~= "" then setNestedField(result, "resources[1].criticality", rvh_crit) end
    local rvh_cve = getNestedField(event, "resp_vulnerable_host.cve")
    if rvh_cve ~= nil and rvh_cve ~= "" then setNestedField(result, "vulnerabilities[1].cve.uid", rvh_cve) end
    mapped_keys["resp_vulnerable_host.hostname"] = true
    mapped_keys["resp_vulnerable_host.host_uid"] = true
    mapped_keys["resp_vulnerable_host.criticality"] = true
    mapped_keys["resp_vulnerable_host.cve"] = true

    -- note -> finding_info.title (msg when note is absent). note is not
    -- marked as mapped, so unmapped.note stays available for existing queries.
    local note_val = getValue(event, "note")
    local title = note_val
    if title == nil or title == "" then title = getValue(event, "msg") end
    setNestedField(result, "finding_info.title", title or "Corelight notice")

    local finding_uid = getValue(event, "uid")
    if finding_uid == nil or finding_uid == "" then
        local parts = {}
        if note_val ~= nil and note_val ~= "" then parts[#parts + 1] = tostring(note_val) end
        if wts ~= nil then parts[#parts + 1] = tostring(wts) end
        if src_ip ~= nil then parts[#parts + 1] = tostring(src_ip) end
        if orig_p ~= nil then parts[#parts + 1] = tostring(orig_p) end
        if dst_ip ~= nil then parts[#parts + 1] = tostring(dst_ip) end
        if resp_p ~= nil then parts[#parts + 1] = tostring(resp_p) end
        if #parts > 0 then finding_uid = table.concat(parts, "_") end
    end
    setNestedField(result, "finding_info.uid", finding_uid or "Unknown")

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- observables
    local obs = {}
    addObservables(obs, "evidences[0].src_endpoint.ip", "IP Address", 2, src_ip)
    addObservables(obs, "evidences[0].dst_endpoint.ip", "IP Address", 2, dst_ip)
    addObservables(obs, "finding_info.title", "Other", 99, getNestedField(result, "finding_info.title"))
    addObservables(obs, "finding_info.uid", "Other", 99, getNestedField(result, "finding_info.uid"))
    addObservables(obs, "resources[0].name", "Hostname", 1, ovh_hostname)
    addObservables(obs, "resources[1].name", "Hostname", 1, rvh_hostname)
    addObservables(obs, "vulnerabilities[0].cve.uid", "Other", 99, ovh_cve)
    addObservables(obs, "vulnerabilities[1].cve.uid", "Other", 99, rvh_cve)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end


-- =========================================================
-- rdp
-- =========================================================

local RDP_COPY_MAPPINGS = {
    { source = "uid",              target = "connection_info.uid" },
    { source = "cookie",           target = "identifier_cookie" },
    { source = "result",           target = "status_detail" },
    { source = "client_build",     target = "protocol_ver" },
    { source = "security_protocol",target = "tls.version" },
    { source = "keyboard_layout",  target = "keyboard_info.keyboard_layout" },
    { source = "_path",            target = "metadata.log_name" },
    { source = "_system_name",     target = "metadata.log_provider" },
}

local function processRdpEvents(event)
    local result = {}
    result.class_uid     = 4005
    result.class_name    = "RDP Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 6
    result.activity_name = "Traffic"
    result.type_uid      = 400506
    result.type_name     = "RDP Activity: Traffic"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(RDP_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- endpoints
    local orig_h = getNestedField(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then setNestedField(result, "src_endpoint.ip", orig_h) end
    mapped_keys["id.orig_h"] = true

    local orig_p = tonumber(getNestedField(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    local resp_h = getNestedField(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then setNestedField(result, "dst_endpoint.ip", resp_h) end
    mapped_keys["id.resp_h"] = true

    local resp_p = tonumber(getNestedField(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- client_name -> src_endpoint.name
    local client_name = getValue(event, "client_name")
    if client_name ~= nil and client_name ~= "" then
        setNestedField(result, "src_endpoint.name", client_name)
    end
    mapped_keys["client_name"] = true
    
    local cookie = getValue(event, "cookie")
    if cookie ~= nil and cookie ~= "" then
        setNestedField(result, "identifier_cookie", cookie)
    end
    mapped_keys["cookie"] = true

    -- auth_success -> status_id
    local auth_suc = getValue(event, "auth_success")
    local sid_rdp = 0
    if auth_suc == true or auth_suc == "true" then
        sid_rdp = 1
    elseif auth_suc == false or auth_suc == "false" then
        sid_rdp = 2
    elseif auth_suc ~= nil and auth_suc ~= "" and not isPlaceholder(tostring(auth_suc)) then
        sid_rdp = 99
    end
    setNestedField(result, "status_id", sid_rdp)
    setNestedField(result, "status", STATUS_CAPTIONS[sid_rdp] or "Unknown")
    mapped_keys["auth_success"] = true

    -- desktop dimensions
    local dw = tonumber(getValue(event, "desktop_width"))
    if dw ~= nil then setNestedField(result, "remote_display.physical_width", dw) end
    mapped_keys["desktop_width"] = true

    local dh = tonumber(getValue(event, "desktop_height"))
    if dh ~= nil then setNestedField(result, "remote_display.physical_height", dh) end
    mapped_keys["desktop_height"] = true

    -- requested_color_depth -> extract leading number
    local color_depth_raw = getValue(event, "requested_color_depth")
    if color_depth_raw ~= nil and color_depth_raw ~= "" then
        local cd_s = color_depth_raw
        if type(cd_s) == "table" then cd_s = nil end
        if type(cd_s) ~= "string" then cd_s = tostring(cd_s or "") end
        local cd_num = cd_s:match("^(%d+)")
        if cd_num then setNestedField(result, "remote_display.color_depth", tonumber(cd_num)) end
    end
    mapped_keys["requested_color_depth"] = true

    -- rdfp_hash -> src_endpoint.fingerprints[0] (gated)
    local rdfp = getValue(event, "rdfp_hash")
    if rdfp ~= nil and not isPlaceholder(rdfp) then
        setNestedField(result, "src_endpoint.fingerprints[0].value", rdfp)
        setNestedField(result, "src_endpoint.fingerprints[0].algorithm_id", 99)
        setNestedField(result, "src_endpoint.fingerprints[0].algorithm", "RDFP")
    end
    mapped_keys["rdfp_hash"] = true

    -- inferences -> JSON string at unmapped.inferences
    addArrayFieldUnmapped(event, result, mapped_keys, "inferences")

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- observables
    local obs = {}
    addObservables(obs, "src_endpoint.ip", "IP Address", 2, orig_h)
    addObservables(obs, "dst_endpoint.ip", "IP Address", 2, resp_h)
    addObservables(obs, "src_endpoint.name", "Hostname", 1, client_name)
    addObservables(obs, "identifier_cookie", "User Name", 4, getNestedField(result, "identifier_cookie"))
    addObservables(obs, "src_endpoint.fingerprints[0].value", "Hash", 8, rdfp)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- smb_files
-- =========================================================

local SMB_FILES_COPY_MAPPINGS = {
    { source = "uid",          target = "connection_info.uid" },
    { source = "path",         target = "file.path" },
    { source = "object_path",  target = "share" },
    { source = "fuid",         target = "file.uid" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processSmbFilesEvents(event)
    local result = {}
    result.class_uid     = 4006
    result.class_name    = "SMB Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 400600
    result.type_name     = SMB_FILES_TYPE_CAPTIONS[400600] or "SMB Activity: Unknown"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "file.type_id", 0)
    setNestedField(result, "file.type", "Unknown")
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")
    setNestedField(result, "metadata.profiles", {})

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(SMB_FILES_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- id endpoints
    local orig_h = getNestedField(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then setNestedField(result, "src_endpoint.ip", orig_h) end
    mapped_keys["id.orig_h"] = true

    local orig_p = tonumber(getNestedField(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    local resp_h = getNestedField(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then setNestedField(result, "dst_endpoint.ip", resp_h) end
    mapped_keys["id.resp_h"] = true

    local resp_p = tonumber(getNestedField(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction
    local dir_id, dir_name = computeDirection(orig_h, resp_h)
    setNestedField(result, "connection_info.direction_id", dir_id)
    setNestedField(result, "connection_info.direction", dir_name)

    -- vlan
    local vlan_val = getNestedField(event, "id.vlan")
    if vlan_val ~= nil and vlan_val ~= "" then
        setNestedField(result, "src_endpoint.vlan_uid", tostring(vlan_val))
    end
    mapped_keys["id.vlan"] = true

    -- name -> file.name
    local name_val = getValue(event, "name")
    if name_val ~= nil and name_val ~= "" then
        setNestedField(result, "file.name", name_val)
    end
    mapped_keys["name"] = true

    -- path -> file.path
    local path_val = getValue(event, "path")
    if path_val ~= nil and path_val ~= "" then
        setNestedField(result, "file.path", path_val)
    end
    mapped_keys["path"] = true

    -- size -> file.size
    local sz = tonumber(getValue(event, "size"))
    if sz ~= nil then setNestedField(result, "file.size", sz) end
    mapped_keys["size"] = true

    -- times.created / modified / accessed
    local tc = convertToMilliseconds(tostring(getNestedField(event, "times.created") or ""))
    if tc ~= nil then setNestedField(result, "file.created_time", tc) end
    local tm = convertToMilliseconds(tostring(getNestedField(event, "times.modified") or ""))
    if tm ~= nil then setNestedField(result, "file.modified_time", tm) end
    local ta = convertToMilliseconds(tostring(getNestedField(event, "times.accessed") or ""))
    if ta ~= nil then setNestedField(result, "file.accessed_time", ta) end
    mapped_keys["times.created"] = true
    mapped_keys["times.modified"] = true
    mapped_keys["times.accessed"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- observables
    local obs = {}
    addObservables(obs, "src_endpoint.ip", "IP Address", 2, orig_h)
    addObservables(obs, "dst_endpoint.ip", "IP Address", 2, resp_h)
    addObservables(obs, "file.name", "File Name", 7, name_val)
    addObservables(obs, "file.path", "File Path", 45, path_val)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end


-- =========================================================
-- smb_mapping
-- =========================================================

local SMB_MAPPING_COPY_MAPPINGS = {
    { source = "uid",          target = "connection_info.uid" },
    { source = "object_path",  target = "share" },
    { source = "path",         target = "file.path" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processSmbMappingEvents(event)
    local result = {}
    result.class_uid     = 4006
    result.class_name    = "SMB Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 400600
    result.type_name     = "SMB Activity: Unknown"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "file.type_id", 0)
    setNestedField(result, "file.type", "Unknown")
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "smb_mapping")
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(SMB_MAPPING_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- endpoints
    local orig_h = getNestedField(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then setNestedField(result, "src_endpoint.ip", orig_h) end
    mapped_keys["id.orig_h"] = true

    local orig_p = tonumber(getNestedField(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    local resp_h = getNestedField(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then setNestedField(result, "dst_endpoint.ip", resp_h) end
    mapped_keys["id.resp_h"] = true

    local resp_p = tonumber(getNestedField(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction
    local dir_id, dir_name = computeDirection(orig_h, resp_h)
    setNestedField(result, "connection_info.direction_id", dir_id)
    setNestedField(result, "connection_info.direction", dir_name)

    -- share_type -> share_type_id + share_type
    local st_raw = getValue(event, "share_type")
    local st_id = 0
    if st_raw ~= nil and st_raw ~= "" then
        st_id = SHARE_TYPE_MAP[tostring(st_raw):upper()] or 99
    end
    setNestedField(result, "share_type_id", st_id)
    if st_id == 99 then
        setNestedField(result, "share_type", tostring(st_raw))
    else
        local st_captions = { [0]="Unknown", [1]="File", [2]="Pipe", [3]="Print", [99]="Other" }
        setNestedField(result, "share_type", st_captions[st_id] or "Unknown")
    end
    mapped_keys["share_type"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- observables
    local obs = {}
    local share_obs = getValue(event, "object_path")
    addObservables(obs, "src_endpoint.ip", "IP Address", 2, orig_h)
    addObservables(obs, "dst_endpoint.ip", "IP Address", 2, resp_h)
    addObservables(obs, "share", "Other", 99, share_obs)
    local path_val = getValue(event, "path")
    addObservables(obs, "file.name", "File Name", 7, path_val)
    addObservables(obs, "file.path", "File Path", 45, path_val)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- software
-- =========================================================

local SOFTWARE_COPY_MAPPINGS = {
    { source = "_path",             target = "metadata.log_name" },
    { source = "_system_name",      target = "metadata.log_provider" },
    { source = "unparsed_version",  target = "product.version" },
}

local function processSoftwareEvents(event)
    local result = {}
    result.class_uid     = 5020
    result.class_name    = "Software Inventory Info"
    result.category_uid  = 5
    result.category_name = "Discovery"
    result.activity_id   = 1
    result.activity_name = "Log"
    result.type_uid      = 502001
    result.type_name     = "Software Inventory Info: Log"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "device.type_id", 0)
    setNestedField(result, "device.type", "Unknown")
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "software")
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(SOFTWARE_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- host -> device.ip (fallback host_header)
    local host_val = getValue(event, "host")
    local dev_ip = nil
    if host_val ~= nil and host_val ~= "" then
        dev_ip = host_val
    else
        local hh = getValue(event, "host_header")
        if hh ~= nil and hh ~= "" then dev_ip = hh end
    end
    if dev_ip ~= nil then setNestedField(result, "device.ip", dev_ip) end
    mapped_keys["host"] = true

    -- name -> product.name
    local name_val = getValue(event, "name")
    if name_val ~= nil and not isPlaceholder(name_val) then
        setNestedField(result, "product.name", name_val)
    end
    mapped_keys["name"] = true

    -- software_type -> product.feature.name
    local sw_type = getValue(event, "software_type")
    if sw_type ~= nil and not isPlaceholder(sw_type) then
        setNestedField(result, "product.feature.name", sw_type)
    end
    mapped_keys["software_type"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- observables
    local obs = {}
    addObservables(obs, "device.ip", "IP Address", 2, dev_ip)
    addObservables(obs, "product.name", "Other", 99, name_val)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end


-- =========================================================
-- ssh
-- =========================================================

local SSH_COPY_MAPPINGS = {
    { source = "uid",                  target = "connection_info.uid" },
    { source = "hasshAlgorithms",      target = "client_hassh.algorithm" },
    { source = "hasshServerAlgorithms",target = "server_hassh.algorithm" },
    { source = "_path",                target = "metadata.log_name" },
    { source = "_system_name",         target = "metadata.log_provider" },
}

local function processSshEvents(event)
    local result = {}
    result.class_uid     = 4007
    result.class_name    = "SSH Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 6
    result.activity_name = "Traffic"
    result.type_uid      = 400706
    result.type_name     = "SSH Activity: Traffic"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "app_protocol_name", "ssh")
    setNestedField(result, "connection_info.direction_id", 0)
    setNestedField(result, "connection_info.direction", "Unknown")
    setNestedField(result, "connection_info.protocol_name", "tcp")
    setNestedField(result, "connection_info.protocol_num", 6)
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(SSH_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- endpoints
    local orig_h = getNestedField(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then setNestedField(result, "src_endpoint.ip", orig_h) end
    mapped_keys["id.orig_h"] = true

    local orig_p = tonumber(getNestedField(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    local resp_h = getNestedField(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then setNestedField(result, "dst_endpoint.ip", resp_h) end
    mapped_keys["id.resp_h"] = true

    local resp_p = tonumber(getNestedField(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- auth_success -> status_id
    local auth_suc = getValue(event, "auth_success")
    local sid_ssh = 0
    if auth_suc == true or auth_suc == "true" then
        sid_ssh = 1
    elseif auth_suc == false or auth_suc == "false" then
        sid_ssh = 2
    elseif auth_suc ~= nil and auth_suc ~= "" then
        sid_ssh = 99
    end
    setNestedField(result, "status_id", sid_ssh)
    setNestedField(result, "status", STATUS_CAPTIONS[sid_ssh] or "Unknown")
    mapped_keys["auth_success"] = true

    -- version -> protocol_ver (as string)
    local ver = getValue(event, "version")
    if ver ~= nil and ver ~= "" then setNestedField(result, "protocol_ver", tostring(ver)) end
    mapped_keys["version"] = true

    -- hassh -> client_hassh.fingerprint
    local hassh = getValue(event, "hassh")
    if hassh ~= nil and hassh ~= "" then
        setNestedField(result, "client_hassh.fingerprint.value", hassh)
        setNestedField(result, "client_hassh.fingerprint.algorithm_id", 20)
        setNestedField(result, "client_hassh.fingerprint.algorithm", "HASSH")
    end
    mapped_keys["hassh"] = true

    -- hasshServer -> server_hassh.fingerprint
    local hassh_server = getValue(event, "hasshServer")
    if hassh_server ~= nil and hassh_server ~= "" then
        setNestedField(result, "server_hassh.fingerprint.value", hassh_server)
        setNestedField(result, "server_hassh.fingerprint.algorithm_id", 20)
        setNestedField(result, "server_hassh.fingerprint.algorithm", "HASSH")
    end
    mapped_keys["hasshServer"] = true

    -- remote_location.* -> dst_endpoint.location.*
    local city = getNestedField(event, "remote_location.city")
    if city ~= nil and not isPlaceholder(city) then setNestedField(result, "dst_endpoint.location.city", city) end
    local country = getNestedField(event, "remote_location.country_code")
    if country ~= nil and not isPlaceholder(country) then
        setNestedField(result, "dst_endpoint.location.country", country)
    end
    local region = getNestedField(event, "remote_location.region")
    if region ~= nil and not isPlaceholder(region) then
        setNestedField(result, "dst_endpoint.location.region", region)
    end
    local lat = tonumber(getNestedField(event, "remote_location.latitude"))
    if lat ~= nil then setNestedField(result, "dst_endpoint.location.lat", lat) end
    local lon = tonumber(getNestedField(event, "remote_location.longitude"))
    if lon ~= nil then setNestedField(result, "dst_endpoint.location.long", lon) end
    mapped_keys["remote_location"] = true

    -- inferences -> JSON string at unmapped.inferences
    addArrayFieldUnmapped(event, result, mapped_keys, "inferences")

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- observables
    local obs = {}
    local src_ip_obs = getNestedField(result, "src_endpoint.ip")
    local dst_ip_obs = getNestedField(result, "dst_endpoint.ip")
    addObservables(obs, "src_endpoint.ip", "IP Address", 2, src_ip_obs)
    addObservables(obs, "dst_endpoint.ip", "IP Address", 2, dst_ip_obs)
    addObservables(obs, "client_hassh.fingerprint.value", "Hash", 8, hassh)
    addObservables(obs, "server_hassh.fingerprint.value", "Hash", 8, hassh_server)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end


-- =========================================================
-- ssl
-- =========================================================

local SSL_COPY_MAPPINGS = {
    { source = "uid",          target = "connection_info.uid" },
    { source = "cipher",       target = "tls.cipher" },
    { source = "server_name",  target = "tls.sni" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processSslEvents(event)
    local result = {}
    result.class_uid     = 4001
    result.class_name    = "Network Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.severity_id   = 0
    result.severity      = "Unknown"
    setNestedField(result, "tls.version", "Unknown")
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    -- established -> activity_id, type_uid, type_name, status_id, status
    local established = getValue(event, "established")
    local act_id_ssl = 0
    local sid_ssl = 0
    if established == true or established == "true" then
        act_id_ssl = 1
        sid_ssl    = 1
    elseif established == false or established == "false" then
        act_id_ssl = 4
        sid_ssl    = 2
    elseif established ~= nil and established ~= "" then
        sid_ssl = 99
    end
    local act_name_ssl = SSL_ACT_CAPTIONS[act_id_ssl] or "Unknown"
    setNestedField(result, "activity_id", act_id_ssl)
    setNestedField(result, "activity_name", act_name_ssl)
    local type_uid_ssl = 4001 * 100 + act_id_ssl
    setNestedField(result, "type_uid", type_uid_ssl)
    setNestedField(result, "type_name", SSL_TYPE_CAPTIONS[type_uid_ssl] or ("Network Activity: " .. act_name_ssl))
    setNestedField(result, "status_id", sid_ssl)
    if sid_ssl == 99 then setNestedField(result, "status", tostring(established))
    else setNestedField(result, "status", STATUS_CAPTIONS[sid_ssl] or "Unknown") end

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(SSL_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true
    mapped_keys["established"] = true

    -- version -> tls.version (overrides static Unknown)
    local ver_val = getValue(event, "version")
    if ver_val ~= nil and ver_val ~= "" then setNestedField(result, "tls.version", ver_val) end
    mapped_keys["version"] = true

    local sni_matches_cert = getValue(event, "sni_matches_cert")

    -- A severity that reflects the TLS version, handshake outcome, and any
    -- SNI/certificate mismatch, instead of a flat "Unknown" always.
    local tls_sev_id, tls_sev_name = tlsSeverity(getNestedField(result, "tls.version"), established, sni_matches_cert)
    setNestedField(result, "severity_id", tls_sev_id)
    setNestedField(result, "severity", tls_sev_name)

    -- endpoints
    local orig_h = getNestedField(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then setNestedField(result, "src_endpoint.ip", orig_h) end
    mapped_keys["id.orig_h"] = true

    local orig_p = tonumber(getNestedField(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    local resp_h = getNestedField(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then setNestedField(result, "dst_endpoint.ip", resp_h) end
    mapped_keys["id.resp_h"] = true

    local resp_p = tonumber(getNestedField(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction
    local dir_id, dir_name = computeDirection(orig_h, resp_h)
    setNestedField(result, "connection_info.direction_id", dir_id)
    setNestedField(result, "connection_info.direction", dir_name)

    -- ja3 -> tls.ja3_hash
    local ja3 = getValue(event, "ja3")
    if ja3 ~= nil and not isPlaceholder(ja3) then
        setNestedField(result, "tls.ja3_hash.value", ja3)
        setNestedField(result, "tls.ja3_hash.algorithm_id", 1)
        setNestedField(result, "tls.ja3_hash.algorithm", "MD5")
    end
    mapped_keys["ja3"] = true

    -- ja3s -> tls.ja3s_hash (gated)
    local ja3s = getValue(event, "ja3s")
    if ja3s ~= nil and not isPlaceholder(ja3s) then
        setNestedField(result, "tls.ja3s_hash.value", ja3s)
        setNestedField(result, "tls.ja3s_hash.algorithm_id", 1)
        setNestedField(result, "tls.ja3s_hash.algorithm", "MD5")
    end
    mapped_keys["ja3s"] = true

    -- cert_chain_fps[] -> tls.certificate_chain (JSON string)
    local cert_fps = getValue(event, "cert_chain_fps")
    if type(cert_fps) == "table" and #cert_fps > 0 then
        setNestedField(result, "tls.certificate_chain", jsonEncode(cert_fps))
    end
    mapped_keys["cert_chain_fps"] = true

    -- last_alert -> tls.alert
    local last_alert = tonumber(getValue(event, "last_alert"))
    if last_alert ~= nil then setNestedField(result, "tls.alert", last_alert) end
    mapped_keys["last_alert"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)

    -- one-line summary
    setNestedField(result, "message",
        "TLS " .. (getNestedField(result, "tls.sni") or resp_h or "?")
        .. " [" .. (getNestedField(result, "tls.version") or "?") .. "]")

    -- observables
    local obs = {}
    addObservables(obs, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(obs, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    addObservables(obs, "tls.sni", "Hostname", 1, getNestedField(result, "tls.sni"))
    addObservables(obs, "tls.ja3_hash.value", "Hash", 8, getNestedField(result, "tls.ja3_hash.value"))
    addObservables(obs, "tls.ja3s_hash.value", "Hash", 8, getNestedField(result, "tls.ja3s_hash.value"))
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- ssl_agg
-- =========================================================

local SSL_AGG_COPY_MAPPINGS = {
    { source = "id.orig_h",   target = "src_endpoint.ip" },
    { source = "id.resp_h",   target = "dst_endpoint.ip" },
    { source = "cipher",      target = "tls.cipher" },
    { source = "server_name", target = "tls.sni" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processSslAggEvents(event)
    local result = {}
    result.class_uid     = 4001
    result.class_name    = "Network Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 6
    result.activity_name = "Traffic"
    result.type_uid      = 400106
    result.type_name     = "Network Activity: Traffic"
    result.severity_id   = 0
    result.severity      = "Unknown"
    setNestedField(result, "tls.version", "Unknown")
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "ssl_agg")
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    -- established -> activity_id, type_uid, type_name, status_id, status
    local established = getValue(event, "established")
    local act_id_ssl = 0
    local sid_ssl = 0
    if established == true or established == "true" then
        act_id_ssl = 1
        sid_ssl    = 1
    elseif established == false or established == "false" then
        act_id_ssl = 4
        sid_ssl    = 2
    elseif established ~= nil and established ~= "" then
        sid_ssl = 99
    end
    local act_name_ssl = SSL_ACT_CAPTIONS[act_id_ssl] or "Unknown"
    setNestedField(result, "activity_id", act_id_ssl)
    setNestedField(result, "activity_name", act_name_ssl)
    local type_uid_ssl = 4001 * 100 + act_id_ssl
    setNestedField(result, "type_uid", type_uid_ssl)
    setNestedField(result, "type_name", SSL_TYPE_CAPTIONS[type_uid_ssl] or ("Network Activity: " .. act_name_ssl))
    setNestedField(result, "status_id", sid_ssl)
    if sid_ssl == 99 then setNestedField(result, "status", tostring(established))
    else setNestedField(result, "status", STATUS_CAPTIONS[sid_ssl] or "Unknown") end

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(SSL_AGG_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true
    mapped_keys["established"] = true

    -- version -> tls.version (overrides static Unknown)
    local ver_val = getValue(event, "version")
    if ver_val ~= nil and ver_val ~= "" then setNestedField(result, "tls.version", ver_val) end
    mapped_keys["version"] = true

    local sni_matches_cert = getValue(event, "sni_matches_cert")

    -- A severity that reflects the TLS version, handshake outcome, and any
    -- SNI/certificate mismatch, instead of a flat "Unknown" always.
    local tls_sev_id, tls_sev_name = tlsSeverity(getNestedField(result, "tls.version"), established, sni_matches_cert)
    setNestedField(result, "severity_id", tls_sev_id)
    setNestedField(result, "severity", tls_sev_name)

    -- endpoints
    local orig_h = getNestedField(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then setNestedField(result, "src_endpoint.ip", orig_h) end
    mapped_keys["id.orig_h"] = true

    local resp_h = getNestedField(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then setNestedField(result, "dst_endpoint.ip", resp_h) end
    mapped_keys["id.resp_h"] = true

    -- ja3 -> tls.ja3_hash
    local ja3 = getValue(event, "ja3")
    if ja3 ~= nil and not isPlaceholder(ja3) then
        setNestedField(result, "tls.ja3_hash.value", ja3)
        setNestedField(result, "tls.ja3_hash.algorithm_id", 1)
        setNestedField(result, "tls.ja3_hash.algorithm", "MD5")
    end
    mapped_keys["ja3"] = true

    -- ja3s -> tls.ja3s_hash (gated)
    local ja3s = getValue(event, "ja3s")
    if ja3s ~= nil and not isPlaceholder(ja3s) then
        setNestedField(result, "tls.ja3s_hash.value", ja3s)
        setNestedField(result, "tls.ja3s_hash.algorithm_id", 1)
        setNestedField(result, "tls.ja3s_hash.algorithm", "MD5")
    end
    mapped_keys["ja3s"] = true

    -- cert_chain_fps[] -> tls.certificate_chain (JSON string)
    local cert_fps = getValue(event, "cert_chain_fps")
    if type(cert_fps) == "table" and #cert_fps > 0 then
        setNestedField(result, "tls.certificate_chain", jsonEncode(cert_fps))
    end
    mapped_keys["cert_chain_fps"] = true

    -- count
    local cnt = tonumber(getValue(event, "count"))
    if cnt ~= nil then result.count = cnt end
    mapped_keys["count"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)

    -- one-line summary
    setNestedField(result, "message",
        "TLS " .. (getNestedField(result, "tls.sni") or getNestedField(result, "dst_endpoint.ip") or "?")
        .. " [" .. (getNestedField(result, "tls.version") or "?") .. "]")

    -- observables
    local obs = {}
    addObservables(obs, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(obs, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    addObservables(obs, "tls.sni", "Hostname", 1, getNestedField(result, "tls.sni"))
    addObservables(obs, "tls.ja3_hash.value", "Hash", 8, getNestedField(result, "tls.ja3_hash.value"))
    addObservables(obs, "tls.ja3s_hash.value", "Hash", 8, getNestedField(result, "tls.ja3s_hash.value"))
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- ssl_red
-- =========================================================

local SSL_RED_COPY_MAPPINGS = {
    { source = "uid",          target = "connection_info.uid" },
    { source = "cipher",       target = "tls.cipher" },
    { source = "server_name",  target = "tls.sni" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processSslRedEvents(event)
    local result = {}
    result.class_uid     = 4001
    result.class_name    = "Network Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 6
    result.activity_name = "Traffic"
    result.type_uid      = 400106
    result.type_name     = "Network Activity: Traffic"
    result.severity_id   = 0
    result.severity      = "Unknown"
    setNestedField(result, "tls.version", "Unknown")
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    -- established -> activity_id, type_uid, type_name, status_id, status
    local established = getValue(event, "established")
    local act_id_ssl = 0
    local sid_ssl = 0
    if established == true or established == "true" then
        act_id_ssl = 1
        sid_ssl    = 1
    elseif established == false or established == "false" then
        act_id_ssl = 4
        sid_ssl    = 2
    elseif established ~= nil and established ~= "" then
        sid_ssl = 99
    end

    local act_name_ssl = SSL_ACT_CAPTIONS[act_id_ssl] or "Unknown"
    setNestedField(result, "activity_id", act_id_ssl)
    setNestedField(result, "activity_name", act_name_ssl)
    local type_uid_ssl = 4001 * 100 + act_id_ssl
    setNestedField(result, "type_uid", type_uid_ssl)
    setNestedField(result, "type_name", SSL_TYPE_CAPTIONS[type_uid_ssl] or ("Network Activity: " .. act_name_ssl))
    setNestedField(result, "status_id", sid_ssl)
    if sid_ssl == 99 then setNestedField(result, "status", tostring(established))
    else setNestedField(result, "status", STATUS_CAPTIONS[sid_ssl] or "Unknown") end

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(SSL_RED_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true
    mapped_keys["established"] = true

    -- version -> tls.version (overrides static Unknown)
    local ver_val = getValue(event, "version")
    if ver_val ~= nil and ver_val ~= "" then setNestedField(result, "tls.version", ver_val) end
    mapped_keys["version"] = true

    local sni_matches_cert = getValue(event, "sni_matches_cert")

    -- A severity that reflects the TLS version, handshake outcome, and any
    -- SNI/certificate mismatch, instead of a flat "Unknown" always.
    local tls_sev_id, tls_sev_name = tlsSeverity(getNestedField(result, "tls.version"), established, sni_matches_cert)
    setNestedField(result, "severity_id", tls_sev_id)
    setNestedField(result, "severity", tls_sev_name)

    -- endpoints
    local orig_h = getNestedField(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then setNestedField(result, "src_endpoint.ip", orig_h) end
    mapped_keys["id.orig_h"] = true

    local orig_p = tonumber(getNestedField(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    local resp_h = getNestedField(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then setNestedField(result, "dst_endpoint.ip", resp_h) end
    mapped_keys["id.resp_h"] = true

    local resp_p = tonumber(getNestedField(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction
    local dir_id, dir_name = computeDirection(orig_h, resp_h)
    setNestedField(result, "connection_info.direction_id", dir_id)
    setNestedField(result, "connection_info.direction", dir_name)

    -- ja3 -> tls.ja3_hash
    local ja3 = getValue(event, "ja3")
    if ja3 ~= nil and not isPlaceholder(ja3) then
        setNestedField(result, "tls.ja3_hash.value", ja3)
        setNestedField(result, "tls.ja3_hash.algorithm_id", 1)
        setNestedField(result, "tls.ja3_hash.algorithm", "MD5")
    end
    mapped_keys["ja3"] = true

    -- ja3s -> tls.ja3s_hash (gated)
    local ja3s = getValue(event, "ja3s")
    if ja3s ~= nil and not isPlaceholder(ja3s) then
        setNestedField(result, "tls.ja3s_hash.value", ja3s)
        setNestedField(result, "tls.ja3s_hash.algorithm_id", 1)
        setNestedField(result, "tls.ja3s_hash.algorithm", "MD5")
    end
    mapped_keys["ja3s"] = true

    -- cert_chain_fps[] -> tls.certificate_chain (JSON string)
    local cert_fps = getValue(event, "cert_chain_fps")
    if type(cert_fps) == "table" and #cert_fps > 0 then
        setNestedField(result, "tls.certificate_chain", jsonEncode(cert_fps))
    end
    mapped_keys["cert_chain_fps"] = true

    -- last_alert -> tls.alert
    local last_alert = tonumber(getValue(event, "last_alert"))
    if last_alert ~= nil then setNestedField(result, "tls.alert", last_alert) end
    mapped_keys["last_alert"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)

    -- one-line summary
    setNestedField(result, "message",
        "TLS " .. (getNestedField(result, "tls.sni") or resp_h or "?")
        .. " [" .. (getNestedField(result, "tls.version") or "?") .. "]")

    -- observables
    local obs = {}
    addObservables(obs, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(obs, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    addObservables(obs, "tls.sni", "Hostname", 1, getNestedField(result, "tls.sni"))
    addObservables(obs, "tls.ja3_hash.value", "Hash", 8, getNestedField(result, "tls.ja3_hash.value"))
    addObservables(obs, "tls.ja3s_hash.value", "Hash", 8, getNestedField(result, "tls.ja3s_hash.value"))
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end


-- =========================================================
-- suricata_corelight
-- =========================================================

local SURI_COPY_MAPPINGS = {
    { source = "alert.signature",  target = "finding_info.title" },
    { source = "alert.signature",  target = "message" },
    { source = "community_id",     target = "connection_info.community_uid" },
    { source = "uid",              target = "connection_info.uid" },
    { source = "service",          target = "connection_info.protocol_name" },
    { source = "_path",            target = "metadata.log_name" },
    { source = "_system_name",     target = "metadata.log_provider" },
}

local function processSuricataCorelightEvents(event)
    local result = {}
    result.class_uid          = 2004
    result.class_name         = "Detection Finding"
    result.category_uid       = 2
    result.category_name      = "Findings"
    result.activity_id        = 1
    result.activity_name      = "Create"
    result.type_uid           = 200401
    result.type_name          = "Detection Finding: Create"
    setNestedField(result, "finding_info.analytic.type_id", 1)
    setNestedField(result, "finding_info.analytic.type", "Rule")
    setNestedField(result, "evidences[0].connection_info.direction_id", 0)
    setNestedField(result, "evidences[0].connection_info.direction", "Unknown")
    setNestedField(result, "resources[0].name", "Unknown")
    setNestedField(result, "attack_surface_ids", { 2 })
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "suricata_corelight")
    setNestedField(result, "metadata.profiles", { "security_control" })
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(SURI_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- alert.severity -> severity_id (fallback: signature_severity from alert.metadata[])
    local alert_sev = getNestedField(event, "alert.severity")
    local sev_id_s = 0
    if alert_sev ~= nil and alert_sev ~= "" then
        sev_id_s = SURI_SEV_MAP[tonumber(alert_sev)] or 0
    else
        -- look in alert.metadata[] for signature_severity key (colon-delimited, e.g. "signature_severity:Minor")
        local metadata_arr = getNestedField(event, "alert.metadata")
        if type(metadata_arr) == "table" then
            for _, entry in ipairs(metadata_arr) do
                if type(entry) == "string" then
                    local k, v = entry:match("^([^:]+):(.+)$")
                    if k and k:lower() == "signature_severity" then
                        sev_id_s = SURI_SEV_NAME_MAP[tostring(v):upper()] or 0
                        break
                    end
                end
            end
        end
    end
    local SURI_SEV_NAMES = {"Unknown","Informational","Low","Medium","High","Critical","Fatal"}
    setNestedField(result, "severity_id", sev_id_s)
    setNestedField(result, "severity", SURI_SEV_NAMES[sev_id_s + 1] or "Unknown")
    -- mapped_keys["alert.severity"] = true -> Here, we are not marking it as true because we need it for dashboard visualization

    -- alert.action -> allow/deny verdict + status_id
    local alert_action = getNestedField(event, "alert.action")
    local action_info = SURI_ACTION_MAP[tostring(alert_action or ""):lower()] or { action_id = 0, action = "Unknown", status_id = 0 }
    setNestedField(result, "action_id", action_info.action_id)
    setNestedField(result, "action", action_info.action)
    setNestedField(result, "status_id", action_info.status_id)
    if action_info.status_id > 0 then
        setNestedField(result, "status", action_info.status_id == 1 and "Success" or "Failure")
    end
    mapped_keys["alert.action"] = true

    -- alert.signature_id -> finding_info.uid
    local sig_id = getNestedField(event, "alert.signature_id")
    if sig_id ~= nil and sig_id ~= "" then
        setNestedField(result, "finding_info.uid", tostring(sig_id))
    end
    mapped_keys["alert.signature_id"] = true


    -- endpoints
    local orig_h = getNestedField(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then
        setNestedField(result, "src_endpoint.ip", orig_h)
        setNestedField(result, "evidences[0].src_endpoint.ip", orig_h)
    end
    mapped_keys["id.orig_h"] = true

    local orig_p = tonumber(getNestedField(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    local resp_h = getNestedField(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then
        setNestedField(result, "dst_endpoint.ip", resp_h)
        setNestedField(result, "evidences[0].dst_endpoint.ip", resp_h)
    end
    mapped_keys["id.resp_h"] = true

    local resp_p = tonumber(getNestedField(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    local edir_id, edir_name = computeDirection(orig_h, resp_h)
    setNestedField(result, "evidences[0].connection_info.direction_id", edir_id)
    setNestedField(result, "evidences[0].connection_info.direction", edir_name)

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- Endpoint/agent identity
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)

    -- observables
    local obs = {}
    addObservables(obs, "evidences[0].src_endpoint.ip", "IP Address", 2, orig_h)
    addObservables(obs, "evidences[0].dst_endpoint.ip", "IP Address", 2, resp_h)
    addObservables(obs, "finding_info.title", "Other", 99, getNestedField(result, "finding_info.title"))
    addObservables(obs, "finding_info.uid", "Other", 99, getNestedField(result, "finding_info.uid"))
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- vpn
-- =========================================================

local VPN_COPY_MAPPINGS = {
    { source = "uid",          target = "connection_info.uid" },
    { source = "proto",        target = "connection_info.protocol_name" },
    { source = "service",      target = "app_protocol_name" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name",     target = "metadata.log_provider" },
}

local function processVpnEvents(event)
    local result = {}
    result.class_uid     = 4014
    result.class_name    = "Tunnel Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 401400
    result.type_name     = "Tunnel Activity: Unknown"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(VPN_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- endpoints
    local orig_h = getNestedField(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then setNestedField(result, "src_endpoint.ip", orig_h) end
    mapped_keys["id.orig_h"] = true

    local orig_p = tonumber(getNestedField(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    local resp_h = getNestedField(event, "id.resp_h")
    if resp_h ~= nil and not isPlaceholder(resp_h) then
        setNestedField(result, "dst_endpoint.ip", resp_h)
    end
    mapped_keys["id.resp_h"] = true

    local resp_p = tonumber(getNestedField(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction
    local dir_id, dir_name = computeDirection(orig_h, resp_h)
    setNestedField(result, "connection_info.direction_id", dir_id)
    setNestedField(result, "connection_info.direction", dir_name)

    -- duration -> milliseconds
    local dur = tonumber(getValue(event, "duration"))
    if dur ~= nil then setNestedField(result, "duration", math.floor(dur * 1000)) end
    mapped_keys["duration"] = true

    -- traffic bytes
    local ob = tonumber(getValue(event, "orig_bytes"))
    if ob ~= nil then setNestedField(result, "traffic.bytes_out", ob) end
    mapped_keys["orig_bytes"] = true

    local rb = tonumber(getValue(event, "resp_bytes"))
    if rb ~= nil then setNestedField(result, "traffic.bytes_in", rb) end
    mapped_keys["resp_bytes"] = true

    -- location fields
    local orig_cc = getValue(event, "orig_cc")
    if orig_cc ~= nil and not isPlaceholder(orig_cc) then
        setNestedField(result, "src_endpoint.location.country", orig_cc)
    end
    mapped_keys["orig_cc"] = true

    local orig_city = getValue(event, "orig_city")
    if orig_city ~= nil and not isPlaceholder(orig_city) then
        setNestedField(result, "src_endpoint.location.city", orig_city)
    end
    mapped_keys["orig_city"] = true

    local orig_region = getValue(event, "orig_region")
    if orig_region ~= nil and not isPlaceholder(orig_region) then
        setNestedField(result, "src_endpoint.location.region", orig_region)
    end
    mapped_keys["orig_region"] = true

    local resp_cc = getValue(event, "resp_cc")
    if resp_cc ~= nil and not isPlaceholder(resp_cc) then
        setNestedField(result, "dst_endpoint.location.country", resp_cc)
    end
    mapped_keys["resp_cc"] = true

    local resp_city = getValue(event, "resp_city")
    if resp_city ~= nil and not isPlaceholder(resp_city) then
        setNestedField(result, "dst_endpoint.location.city", resp_city)
    end
    mapped_keys["resp_city"] = true

    local resp_region = getValue(event, "resp_region")
    if resp_region ~= nil and not isPlaceholder(resp_region) then
        setNestedField(result, "dst_endpoint.location.region", resp_region)
    end
    mapped_keys["resp_region"] = true

    -- inferences -> JSON string at unmapped.inferences
    addArrayFieldUnmapped(event, result, mapped_keys, "inferences")

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- observables
    local sys_name_obs = getValue(event, "_system_name")
    local obs = {}
    addObservables(obs, "src_endpoint.ip", "IP Address", 2, orig_h)
    addObservables(obs, "dst_endpoint.ip", "IP Address", 2, resp_h)
    addObservables(obs, "metadata.reporter.name", "Hostname", 1, sys_name_obs)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end


-- =========================================================
-- corelight_metrics_iface
-- =========================================================

local CM_IFACE_COPY_MAPPINGS = {
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processCorelightMetricsIfaceEvents(event)
    local result = {}
    result.class_uid     = 0
    result.class_name    = "Base Event"
    result.category_uid  = 0
    result.category_name = "Uncategorized"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 0
    result.type_name     = "Base Event: Unknown"
    result.severity_id   = 0
    result.severity      = "Unknown"
    setNestedField(result, "device.type_id", 0)
    setNestedField(result, "device.type", "Unknown")
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.profiles", { "host" })
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(CM_IFACE_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true


    -- observables: device.hostname from _system_name
    local obs = {}
    local sys_name = getValue(event, "_system_name")
    addObservables(obs, "device.hostname", "Hostname", 1, sys_name)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- corelight_metrics_memory
-- =========================================================

local CM_MEMORY_COPY_MAPPINGS = {
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processCorelightMetricsMemoryEvents(event)
    local result = {}
    result.class_uid     = 0
    result.class_name    = "Base Event"
    result.category_uid  = 0
    result.category_name = "Uncategorized"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 0
    result.type_name     = "Base Event: Unknown"
    result.severity_id   = 0
    result.severity      = "Unknown"
    setNestedField(result, "device.type_id", 0)
    setNestedField(result, "device.type", "Unknown")
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.profiles", { "host" })
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(CM_MEMORY_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true


    -- observables: device.hostname from _system_name
    local obs = {}
    local sys_name = getValue(event, "_system_name")
    addObservables(obs, "device.hostname", "Hostname", 1, sys_name)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- corelight_metrics_bro
-- =========================================================

local CM_BRO_COPY_MAPPINGS = {
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processCorelightMetricsBroEvents(event)
    local result = {}
    result.class_uid     = 0
    result.class_name    = "Base Event"
    result.category_uid  = 0
    result.category_name = "Uncategorized"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 0
    result.type_name     = "Base Event: Unknown"
    result.severity_id   = 0
    result.severity      = "Unknown"
    setNestedField(result, "device.type_id", 0)
    setNestedField(result, "device.type", "Unknown")
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.profiles", { "host" })
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(CM_BRO_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- observables: device.hostname from _system_name
    local obs = {}
    local sys_name = getValue(event, "_system_name")
    addObservables(obs, "device.hostname", "Hostname", 1, sys_name)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are placed under unmapped.*, without zero-valued
    -- counters (see withoutZeroCounters).
    copyUnmappedFields(withoutZeroCounters(event), result, mapped_keys)
    return result
end

-- =========================================================
-- corelight_metrics_system
-- =========================================================

local CM_SYSTEM_COPY_MAPPINGS = {
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processCorelightMetricsSystemEvents(event)
    local result = {}
    result.class_uid     = 5001
    result.class_name    = "Device Inventory Info"
    result.category_uid  = 5
    result.category_name = "Discovery"
    result.activity_id   = 1
    result.activity_name = "Log"
    result.type_uid      = 500101
    result.type_name     = "Device Inventory Info: Log"
    result.severity_id   = 0
    result.severity      = "Unknown"
    setNestedField(result, "device.type_id", 0)
    setNestedField(result, "device.type", "Unknown")
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "corelight_metrics_system")
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(CM_SYSTEM_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true


    -- observables: device.hostname from _system_name
    local obs = {}
    local sys_name = getValue(event, "_system_name")
    addObservables(obs, "device.hostname", "Hostname", 1, sys_name)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- corelight_metrics_zeek_doctor
-- =========================================================

local CM_ZEEK_DOCTOR_COPY_MAPPINGS = {
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processCorelightMetricsZeekDoctorEvents(event)
    local result = {}
    result.class_uid     = 0
    result.class_name    = "Base Event"
    result.category_uid  = 0
    result.category_name = "Uncategorized"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 0
    result.type_name     = "Base Event: Unknown"
    result.severity_id   = 0
    result.severity      = "Unknown"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "corelight_metrics_zeek_doctor")
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(CM_ZEEK_DOCTOR_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true


    -- observables: device.hostname from _system_name
    local obs = {}
    local sys_name = getValue(event, "_system_name")
    addObservables(obs, "device.hostname", "Hostname", 1, sys_name)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end


-- =========================================================
-- x509
-- =========================================================

local X509_COPY_MAPPINGS = {
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processX509Events(event)
    local result = {}
    result.class_uid     = 4001
    result.class_name    = "Network Activity"
    result.category_uid  = 4
    result.category_name = "Network Activity"
    result.activity_id   = 0
    result.activity_name = "Unknown"
    result.type_uid      = 400100
    result.type_name     = "Network Activity: Unknown"
    result.severity_id   = 0
    result.severity      = "Unknown"
    setNestedField(result, "tls.version", "Unknown")
    setNestedField(result, "src_endpoint.name", "Unknown")
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "x509")
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(X509_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- certificate.issuer -> tls.certificate.issuer
    local issuer  = getNestedField(event, "certificate.issuer")
    if issuer ~= nil and not isPlaceholder(issuer) then setNestedField(result, "tls.certificate.issuer", issuer) end        
    mapped_keys["certificate.issuer"] = true

    -- certificate.serial -> tls.certificate.serial_number
    local serial  = getNestedField(event, "certificate.serial")
    if serial ~= nil and not isPlaceholder(serial) then setNestedField(result, "tls.certificate.serial_number", serial) end
    mapped_keys["certificate.serial"] = true

    -- certificate.subject -> tls.certificate.subject
    local subject = getNestedField(event, "certificate.subject")
    if subject ~= nil and subject ~= "" then
        setNestedField(result, "tls.certificate.subject", subject)
    end
    mapped_keys["certificate.subject"] = true

    -- certificate.not_valid_after -> tls.certificate.expiration_time
    local not_after = convertToMilliseconds(tostring(getNestedField(event, "certificate.not_valid_after") or ""))
    if not_after ~= nil then setNestedField(result, "tls.certificate.expiration_time", not_after) end
    mapped_keys["certificate.not_valid_after"] = true

    -- certificate.version -> tls.certificate.version
    local cert_ver = getNestedField(event, "certificate.version")
    if cert_ver ~= nil and cert_ver ~= "" then
        setNestedField(result, "tls.certificate.version", tostring(cert_ver))
    end
    mapped_keys["certificate.version"] = true

    -- fingerprint -> tls.certificate.fingerprints[0] (gated on non-empty)
    local fp = getValue(event, "fingerprint")
    if fp ~= nil and not isPlaceholder(fp) then
        setNestedField(result, "tls.certificate.fingerprints[0].value", fp)
        setNestedField(result, "tls.certificate.fingerprints[0].algorithm_id", 3)
        setNestedField(result, "tls.certificate.fingerprints[0].algorithm", "SHA-256")
    end
    mapped_keys["fingerprint"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- observables
    local fp_obs = getValue(event, "fingerprint")
    local obs = {}
    addObservables(obs, "tls.certificate.issuer", "Other", 99, issuer)
    addObservables(obs, "tls.certificate.subject", "Other", 99, getNestedField(event, "certificate.subject"))
    addObservables(obs, "tls.certificate.serial_number", "Serial Number", 37, serial)
    addObservables(obs, "tls.certificate.fingerprints[0].value", "Hash", 8, fp_obs)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- anomaly
-- =========================================================

local ANOMALY_COPY_MAPPINGS = {
    { source = "use_case",             target = "finding_info.title" },
    { source = "use_case_description", target = "finding_info.desc" },
    { source = "_path",                target = "metadata.log_name" },
    { source = "_system_name",         target = "metadata.log_provider" },
}

local function processAnomalyEvents(event)
    local result = {}
    result.class_uid     = 2004
    result.class_name    = "Detection Finding"
    result.category_uid  = 2
    result.category_name = "Findings"
    result.activity_id   = 1
    result.activity_name = "Create"
    result.type_uid      = 200401
    result.type_name     = "Detection Finding: Create"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "anomaly")
    setNestedField(result, "metadata.profiles", {})
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(ANOMALY_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- uid  -> connection_info.uid
    local uid_val = getValue(event, "uid")
    if uid_val ~= nil and uid_val ~= "" then
        setNestedField(result, "connection_info.uid", uid_val)
    end
    mapped_keys["uid"] = true

    -- item_score -> confidence_score
    local item_score = tonumber(getValue(event, "item_score"))
    if item_score ~= nil then setNestedField(result, "confidence_score", item_score) end
    mapped_keys["item_score"] = true

    -- id.orig_h -> evidences[0].src_endpoint.ip
    local orig_h = getNestedField(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then
        setNestedField(result, "evidences[0].src_endpoint.ip", orig_h)
    end
    mapped_keys["id.orig_h"] = true

    local orig_p = tonumber(getNestedField(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "evidences[0].src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    -- id.resp_h -> evidences[0].dst_endpoint.ip
    local resp_h = getNestedField(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then
        setNestedField(result, "evidences[0].dst_endpoint.ip", resp_h)
    end
    mapped_keys["id.resp_h"] = true

    local resp_p = tonumber(getNestedField(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "evidences[0].dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction for evidences[0].connection_info
    local edir_id, edir_name = computeDirection(orig_h, resp_h)
    setNestedField(result, "evidences[0].connection_info.direction_id", edir_id)
    setNestedField(result, "evidences[0].connection_info.direction", edir_name)

    -- id.vlan -> evidences[0].src_endpoint.vlan_uid
    local id_vlan = getNestedField(event, "id.vlan")
    if id_vlan ~= nil and id_vlan ~= "" then
        setNestedField(result, "evidences[0].src_endpoint.vlan_uid", tostring(id_vlan))
    end
    mapped_keys["id.vlan"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- observables
    local entity_val = getValue(event, "entity")
    local item_val = getValue(event, "item")
    local obs = {}
    addObservables(obs, "evidences[0].src_endpoint.ip", "IP Address", 2, orig_h)
    addObservables(obs, "evidences[0].dst_endpoint.ip", "IP Address", 2, resp_h)
    addObservables(obs, "entity", "Other", 99, entity_val)
    addObservables(obs, "item", "Other", 99, item_val)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- net_perf
-- =========================================================

local NET_PERF_COPY_MAPPINGS = {
    { source = "trigger",      target = "finding_info.title" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
    { source = "uid",          target = "connection_info.uid" },
    { source = "total",        target = "count" },
}

local function processNetPerfEvents(event)
    local result = {}
    result.class_uid     = 2004
    result.class_name    = "Detection Finding"
    result.category_uid  = 2
    result.category_name = "Findings"
    result.activity_id   = 1
    result.activity_name = "Create"
    result.type_uid      = 200401
    result.type_name     = "Detection Finding: Create"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "net_perf")
    setNestedField(result, "metadata.profiles", {})
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(NET_PERF_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- window -> duration
    local window = tonumber(getValue(event, "window"))
    if window ~= nil then setNestedField(result, "duration", math.floor(window * 1000)) end
    mapped_keys["window"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- host / domain -> observables[].value
    local host_val = getValue(event, "host")
    local domain_val = getValue(event, "domain")
    local obs = {}
    addObservables(obs, "host", "IP Address", 2, host_val)
    addObservables(obs, "domain", "Hostname", 1, domain_val)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- yara_corelight
-- =========================================================

local YARA_CORELIGHT_COPY_MAPPINGS = {
    { source = "uid",          target = "connection_info.uid" },
    { source = "match_rule",   target = "finding_info.title" },
    { source = "_path",        target = "metadata.log_name" },
    { source = "_system_name", target = "metadata.log_provider" },
}

local function processYaraCorelightEvents(event)
    local result = {}
    result.class_uid     = 2004
    result.class_name    = "Detection Finding"
    result.category_uid  = 2
    result.category_name = "Findings"
    result.activity_id   = 1
    result.activity_name = "Create"
    result.type_uid      = 200401
    result.type_name     = "Detection Finding: Create"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "yara_corelight")
    setNestedField(result, "metadata.profiles", {})
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(YARA_CORELIGHT_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- last_seen_ts -> finding_info.last_seen_time
    local last_seen = convertToMilliseconds(tostring(getValue(event, "last_seen_ts") or ""))
    if last_seen ~= nil then setNestedField(result, "finding_info.last_seen_time", last_seen) end
    mapped_keys["last_seen_ts"] = true

    -- id.orig_h -> evidences[0].src_endpoint.ip
    local orig_h = getNestedField(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then
        setNestedField(result, "evidences[0].src_endpoint.ip", orig_h)
    end
    mapped_keys["id.orig_h"] = true

    local orig_p = tonumber(getNestedField(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "evidences[0].src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    -- id.resp_h -> evidences[0].dst_endpoint.ip
    local resp_h = getNestedField(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then
        setNestedField(result, "evidences[0].dst_endpoint.ip", resp_h)
    end
    mapped_keys["id.resp_h"] = true

    local resp_p = tonumber(getNestedField(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "evidences[0].dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction for evidences[0].connection_info
    local edir_id, edir_name = computeDirection(orig_h, resp_h)
    setNestedField(result, "evidences[0].connection_info.direction_id", edir_id)
    setNestedField(result, "evidences[0].connection_info.direction", edir_name)

    -- fuid / file_name / mime_type -> evidences[0].file.*
    local fuid = getValue(event, "fuid")
    if fuid ~= nil and fuid ~= "" then setNestedField(result, "evidences[0].file.uid", fuid) end
    mapped_keys["fuid"] = true

    local file_name = getValue(event, "file_name")
    if file_name ~= nil and file_name ~= "" then setNestedField(result, "evidences[0].file.name", file_name) end
    mapped_keys["file_name"] = true

    local mime_type = getValue(event, "mime_type")
    if mime_type ~= nil and mime_type ~= "" then setNestedField(result, "evidences[0].file.mime_type", mime_type) end
    mapped_keys["mime_type"] = true

    -- md5 / sha1 / sha256 -> evidences[0].file.hashes[]
    local hashes = {}
    for _, f in ipairs(FILE_HASH_FIELDS) do
        local v = getValue(event, f.src)
        if v ~= nil and v ~= "" then
            hashes[#hashes + 1] = { value = tostring(v), algorithm = f.alg, algorithm_id = f.alg_id }
        end
    end
    if #hashes > 0 then setNestedField(result, "evidences[0].file.hashes", hashes) end
    mapped_keys["md5"] = true
    mapped_keys["sha1"] = true
    mapped_keys["sha256"] = true

    -- match_tags[] -> finding_info.tags
    local match_tags = getValue(event, "match_tags")
    if type(match_tags) == "table" and #match_tags > 0 then
        setNestedField(result, "finding_info.tags", match_tags)
    end
    mapped_keys["match_tags"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- observables
    local obs = {}
    addObservables(obs, "evidences[0].src_endpoint.ip", "IP Address", 2, orig_h)
    addObservables(obs, "evidences[0].dst_endpoint.ip", "IP Address", 2, resp_h)
    addObservables(obs, "evidences[0].file.name", "File Name", 7, file_name)
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- corelight_ml_results
-- =========================================================

local CORELIGHT_ML_RESULTS_COPY_MAPPINGS = {
    { source = "uid",                target = "connection_info.uid" },
    { source = "predicted_tag_name", target = "finding_info.title" },
    { source = "path",               target = "evidences[0].connection_info.protocol_name" },
    { source = "_path",              target = "metadata.log_name" },
    { source = "_system_name",       target = "metadata.log_provider" },
}

local function processCorelightMlResultsEvents(event)
    local result = {}
    result.class_uid     = 2004
    result.class_name    = "Detection Finding"
    result.category_uid  = 2
    result.category_name = "Findings"
    result.activity_id   = 1
    result.activity_name = "Create"
    result.type_uid      = 200401
    result.type_name     = "Detection Finding: Create"
    result.severity_id   = 1
    result.severity      = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.product.uid", "corelight_ml_results")
    setNestedField(result, "metadata.profiles", {})
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    local ts_val = convertToMilliseconds(tostring(getValue(event, "ts") or ""))
    if ts_val == nil then ts_val = convertToMilliseconds(tostring(getValue(event, "_write_ts") or "")) end
    if ts_val ~= nil then result.time = ts_val end

    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    local mapped_keys = {}
    for _, m in ipairs(CORELIGHT_ML_RESULTS_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end
    mapped_keys["ts"] = true
    mapped_keys["_write_ts"] = true

    -- id.orig_h -> evidences[0].src_endpoint.ip
    local orig_h = getNestedField(event, "id.orig_h")
    if orig_h ~= nil and orig_h ~= "" then
        setNestedField(result, "evidences[0].src_endpoint.ip", orig_h)
    end
    mapped_keys["id.orig_h"] = true

    local orig_p = tonumber(getNestedField(event, "id.orig_p"))
    if orig_p ~= nil then setNestedField(result, "evidences[0].src_endpoint.port", orig_p) end
    mapped_keys["id.orig_p"] = true

    -- id.resp_h -> evidences[0].dst_endpoint.ip
    local resp_h = getNestedField(event, "id.resp_h")
    if resp_h ~= nil and resp_h ~= "" then
        setNestedField(result, "evidences[0].dst_endpoint.ip", resp_h)
    end
    mapped_keys["id.resp_h"] = true

    local resp_p = tonumber(getNestedField(event, "id.resp_p"))
    if resp_p ~= nil then setNestedField(result, "evidences[0].dst_endpoint.port", resp_p) end
    mapped_keys["id.resp_p"] = true

    -- direction for evidences[0].connection_info
    local edir_id, edir_name = computeDirection(orig_h, resp_h)
    setNestedField(result, "evidences[0].connection_info.direction_id", edir_id)
    setNestedField(result, "evidences[0].connection_info.direction", edir_name)

    -- predicted_probability -> confidence_score
    local pred_prob = tonumber(getValue(event, "predicted_probability"))
    if pred_prob ~= nil then setNestedField(result, "confidence_score", pred_prob) end
    mapped_keys["predicted_probability"] = true

    -- attack_probability -> risk_score
    local attack_prob = tonumber(getValue(event, "attack_probability"))
    if attack_prob ~= nil then setNestedField(result, "risk_score", attack_prob) end
    mapped_keys["attack_probability"] = true

    -- Raw event
    setNestedField(result, "unmapped.raw_message", jsonEncode(event))

    -- domain / entity -> observables[].value
    local domain_val = getValue(event, "domain")
    local entity_val = getValue(event, "entity")
    local obs = {}
    addObservables(obs, "evidences[0].src_endpoint.ip", "IP Address", 2, orig_h)
    addObservables(obs, "evidences[0].dst_endpoint.ip", "IP Address", 2, resp_h)
    addObservables(obs, "domain", "Hostname", 1, domain_val)
    addObservables(obs, "entity", "Other", 99, entity_val)
    if #obs > 0 then result.observables = obs end
    mapped_keys["domain"] = true
    mapped_keys["entity"] = true

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- unknown events (any _path without a dedicated handler)
-- =========================================================
-- processEvent calls processUnknownEvents for any _path that findEventType
-- does not recognise (weird, dce_rpc, ldap, ntlm, smtp, dhcp, bacnet,
-- known_*, ...) and for events with no _path at all. It maps the fields that
-- Corelight logs have in common, so these logs are searchable by IP, port,
-- uid and sensor and carry observables like the dedicated handlers:
--
--   ts / _write_ts              -> time / metadata.logged_time
--   _path                       -> metadata.log_name, metadata.product.uid
--   _system_name                -> metadata.log_provider
--   uid                         -> connection_info.uid
--   community_id                -> connection_info.community_uid
--   id.orig_h / id.orig_p       -> src_endpoint.ip / src_endpoint.port
--   id.resp_h / id.resp_p       -> dst_endpoint.ip / dst_endpoint.port
--   orig_l2_addr / resp_l2_addr -> src_endpoint.mac / dst_endpoint.mac
--   id.vlan (or vlan)           -> src_endpoint.vlan_uid
--   id.orig_h_name.vals / id.resp_h_name.vals -> src/dst_endpoint.hostname
--   proto                       -> connection_info.protocol_name / protocol_num
--   id.orig_ep_* / id.resp_ep_* -> src_endpoint.uid, hostname / dst_endpoint.uid
--   local_orig / local_resp     -> connection_info.direction (IP-range
--                                  heuristic when the flags are absent)
--
-- Logs without a conn_id use these instead:
--   client_addr / server_addr / mac (dhcp) -> src/dst_endpoint.ip, src_endpoint.mac
--   uids[] (dhcp, multi-connection logs)   -> connection_info.uid (array)
--   host_ip / host_vlan (known_*)          -> device.ip / device.vlan_uid
--
-- Class: logs with a source or destination IP become 4001 Network Activity
-- with activity Other (99); all others stay 0 Base Event.
--
-- All other fields go to unmapped.<original name>. The full original event is
-- kept in unmapped.raw_message, except for corelight_metrics_* logs.

local GENERIC_PROTO_NUM = { tcp = 6, udp = 17, icmp = 1, icmp6 = 58, sctp = 132 }

local GENERIC_COPY_MAPPINGS = {
    { source = "_path",        target = "metadata.log_name" },
    { source = "_path",        target = "metadata.product.uid" },
    { source = "_system_name", target = "metadata.log_provider" },
    { source = "uid",          target = "connection_info.uid" },
    { source = "community_id", target = "connection_info.community_uid" },
    { source = "orig_l2_addr", target = "src_endpoint.mac" },
    { source = "resp_l2_addr", target = "dst_endpoint.mac" },
}

-- Direction from local_orig/local_resp when present, otherwise from the IP ranges.
local function genericDirection(event, src_ip, dst_ip)
    local dir_id, dir_name = localNetsDirection(event)
    if dir_id ~= nil then return dir_id, dir_name end
    return computeDirection(src_ip, dst_ip)
end

-- The field's value (first element for an array), or nil when it is empty or a placeholder.
local function genericScalar(event, key)
    local v = getValue(event, key)
    if type(v) == "table" then v = v[1] end
    if v == nil or isPlaceholder(v) then return nil end
    return v
end

local function processUnknownEvents(event)
    local result = {}
    local mapped_keys = {}
    local log_name = tostring(getValue(event, "_path") or "unknown")

    local src_ip = genericScalar(event, "id.orig_h")
    local dst_ip = genericScalar(event, "id.resp_h")
    local src_key, dst_key = "id.orig_h", "id.resp_h"
    -- dhcp logs carry client_addr/server_addr instead of id.orig_h/id.resp_h
    if src_ip == nil and dst_ip == nil then
        src_ip = genericScalar(event, "client_addr")
        dst_ip = genericScalar(event, "server_addr")
        src_key, dst_key = "client_addr", "server_addr"
    end
    local is_network = (src_ip ~= nil or dst_ip ~= nil)

    if is_network then
        result.class_uid     = 4001
        result.class_name    = "Network Activity"
        result.category_uid  = 4
        result.category_name = "Network Activity"
        result.activity_id   = 99
        result.activity_name = "Other"
        result.type_uid      = 400199
        result.type_name     = "Network Activity: Other"
    else
        result.class_uid     = 0
        result.class_name    = "Base Event"
        result.category_uid  = 0
        result.category_name = "Uncategorized"
        result.activity_id   = 0
        result.activity_name = "Unknown"
        result.type_uid      = 0
        result.type_name     = "Base Event: Unknown"
    end
    result.severity_id = 1
    result.severity    = "Informational"
    setNestedField(result, "metadata.version", OCSF_VERSION)
    setNestedField(result, "metadata.product.name", PRODUCT_NAME)
    setNestedField(result, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(result, "metadata.profiles", {})
    setNestedField(result, "dataSource.vendor", VENDOR_NAME)
    setNestedField(result, "dataSource.name", PRODUCT_NAME)
    setNestedField(result, "dataSource.category", "security")

    -- ts (first element if it is an array) -> time, falling back to _write_ts;
    -- _write_ts -> metadata.logged_time
    local ts_raw = getValue(event, "ts")
    if type(ts_raw) == "table" then ts_raw = ts_raw[1] end
    local ts_val = convertToMilliseconds(tostring(ts_raw or ""))
    local wts = convertToMilliseconds(tostring(getValue(event, "_write_ts") or ""))
    -- a ts/_write_ts that cannot be parsed stays under unmapped.*
    if ts_val ~= nil then mapped_keys["ts"] = true end
    if wts ~= nil then mapped_keys["_write_ts"] = true end
    if ts_val == nil then ts_val = wts end
    if ts_val ~= nil then result.time = ts_val end
    if wts ~= nil then setNestedField(result, "metadata.logged_time", wts) end

    for _, m in ipairs(GENERIC_COPY_MAPPINGS) do
        if copyField(event, result, m.source, m.target) then mapped_keys[m.source] = true end
    end

    -- endpoints
    if src_ip ~= nil then
        setNestedField(result, "src_endpoint.ip", src_ip)
        mapped_keys[src_key] = true
    end
    if dst_ip ~= nil then
        setNestedField(result, "dst_endpoint.ip", dst_ip)
        mapped_keys[dst_key] = true
    end
    if src_key == "client_addr" then
        -- dhcp: mac -> src_endpoint.mac (when orig_l2_addr is absent)
        if getNestedField(result, "src_endpoint.mac") == nil then
            local mac = genericScalar(event, "mac")
            if mac ~= nil then
                setNestedField(result, "src_endpoint.mac", mac)
                mapped_keys["mac"] = true
            end
        end
    end
    -- uids[] -> connection_info.uid (array), for logs such as dhcp that list
    -- several connection uids instead of a single uid
    if getNestedField(result, "connection_info.uid") == nil then
        local uids = getValue(event, "uids")
        if type(uids) == "table" and #uids > 0 then
            setNestedField(result, "connection_info.uid", uids)
            mapped_keys["uids"] = true
        end
    end

    -- host_ip / host_vlan -> device.ip / device.vlan_uid (known_* logs
    -- describe a device, not a connection)
    local host_ip = genericScalar(event, "host_ip")
    if host_ip ~= nil then
        setNestedField(result, "device.ip", host_ip)
        mapped_keys["host_ip"] = true
        local host_vlan = getValue(event, "host_vlan")
        if host_vlan ~= nil and host_vlan ~= "" then
            setNestedField(result, "device.vlan_uid", tostring(host_vlan))
            mapped_keys["host_vlan"] = true
        end
    end
    local orig_p = tonumber(getValue(event, "id.orig_p"))
    if orig_p ~= nil then
        setNestedField(result, "src_endpoint.port", orig_p)
        mapped_keys["id.orig_p"] = true
    end
    local resp_p = tonumber(getValue(event, "id.resp_p"))
    if resp_p ~= nil then
        setNestedField(result, "dst_endpoint.port", resp_p)
        mapped_keys["id.resp_p"] = true
    end

    -- id.vlan (falling back to vlan) -> src_endpoint.vlan_uid
    local vlan_val = getValue(event, "id.vlan")
    if vlan_val ~= nil and vlan_val ~= "" then
        setNestedField(result, "src_endpoint.vlan_uid", tostring(vlan_val))
        mapped_keys["id.vlan"] = true
    else
        vlan_val = getValue(event, "vlan")
        if vlan_val ~= nil and vlan_val ~= "" then
            setNestedField(result, "src_endpoint.vlan_uid", tostring(vlan_val))
            mapped_keys["vlan"] = true
        end
    end

    -- resolved hostnames
    local orig_names = getValue(event, "id.orig_h_name.vals")
    if type(orig_names) == "table" and orig_names[1] ~= nil and orig_names[1] ~= "" then
        setNestedField(result, "src_endpoint.hostname", orig_names[1])
        mapped_keys["id.orig_h_name.vals"] = true
    end
    local resp_names = getValue(event, "id.resp_h_name.vals")
    if type(resp_names) == "table" and resp_names[1] ~= nil and resp_names[1] ~= "" then
        setNestedField(result, "dst_endpoint.hostname", resp_names[1])
        mapped_keys["id.resp_h_name.vals"] = true
    end

    -- Endpoint/agent identity (the agent name overrides src_endpoint.hostname,
    -- as in the conn handler)
    enrichSrcEndpointFromAgent(event, result, mapped_keys, nil)
    enrichDstEndpointFromAgent(event, result, mapped_keys)

    -- proto -> protocol_name + protocol_num
    local proto = getValue(event, "proto")
    if type(proto) == "string" and proto ~= "" then
        local p = proto:lower()
        setNestedField(result, "connection_info.protocol_name", p)
        local pnum = GENERIC_PROTO_NUM[p]
        if pnum ~= nil then setNestedField(result, "connection_info.protocol_num", pnum) end
        mapped_keys["proto"] = true
    end

    -- direction (network logs only)
    if is_network then
        local dir_id, dir_name = genericDirection(event, src_ip, dst_ip)
        setNestedField(result, "connection_info.direction_id", dir_id)
        setNestedField(result, "connection_info.direction", dir_name)
    end

    -- Raw event. Skipped for corelight_metrics_* logs (as in their dedicated
    -- handlers): all their fields are already under unmapped.*, and a second
    -- copy pushes metrics_bro past SDL's 100,000-character event limit.
    if not log_name:match("^corelight_metrics_") then
        setNestedField(result, "unmapped.raw_message", jsonEncode(event))
    end

    -- one-line summary
    if is_network then
        setNestedField(result, "message",
            log_name .. " " .. (getNestedField(result, "connection_info.protocol_name") or "")
            .. (getNestedField(result, "connection_info.protocol_name") and " " or "")
            .. (src_ip or "?") .. " -> " .. (dst_ip or "?"))
    else
        setNestedField(result, "message",
            "Corelight " .. log_name .. " (" .. (getNestedField(result, "metadata.log_provider") or "?") .. ")")
    end

    -- observables
    local obs = {}
    addObservables(obs, "src_endpoint.ip", "IP Address", 2, getNestedField(result, "src_endpoint.ip"))
    addObservables(obs, "dst_endpoint.ip", "IP Address", 2, getNestedField(result, "dst_endpoint.ip"))
    addObservables(obs, "src_endpoint.mac", "MAC Address", 3, getNestedField(result, "src_endpoint.mac"))
    addObservables(obs, "dst_endpoint.mac", "MAC Address", 3, getNestedField(result, "dst_endpoint.mac"))
    addObservables(obs, "src_endpoint.hostname", "Hostname", 1, getNestedField(result, "src_endpoint.hostname"))
    addObservables(obs, "dst_endpoint.hostname", "Hostname", 1, getNestedField(result, "dst_endpoint.hostname"))
    addObservables(obs, "src_endpoint.uid", "Endpoint UID", 40, getNestedField(result, "src_endpoint.uid"))
    addObservables(obs, "connection_info.uid", "Other", 99, getNestedField(result, "connection_info.uid"))
    addObservables(obs, "connection_info.community_uid", "Other", 99, getNestedField(result, "connection_info.community_uid"))
    addObservables(obs, "device.ip", "IP Address", 2, getNestedField(result, "device.ip"))
    if #obs > 0 then result.observables = obs end

    -- The remaining fields are unmapped and will be placed under unmapped.*.
    copyUnmappedFields(event, result, mapped_keys)
    return result
end

-- =========================================================
-- findEventType
-- =========================================================

local function findEventType(event)
    local _path_val = tostring(getValue(event, "_path") or ""):upper()
    if _path_val == "ASSET_CLASSIFICATION" then return "asset_classification"
    elseif _path_val == "CONN" then return "conn"
    elseif _path_val == "CONN_AGG" then return "conn_agg"
    elseif _path_val == "CONN_LONG" then return "conn_long"
    elseif _path_val == "CONN_RED" then return "conn_red"
    elseif _path_val == "CORELIGHT_METRICS_DISK" then return "corelight_metrics_disk"
    elseif _path_val == "DNS" then return "dns"
    elseif _path_val == "DNS_AGG" then return "dns_agg"
    elseif _path_val == "DNS_RED" then return "dns_red"
    elseif _path_val == "ETC_VIZ" then return "etc_viz"
    elseif _path_val == "FILES" then return "files"
    elseif _path_val == "FILES_AGG" then return "files_agg"
    elseif _path_val == "FILES_RED" then return "files_red"
    elseif _path_val == "FTP" then return "ftp"
    elseif _path_val == "HTTP" then return "http"
    elseif _path_val == "HTTP2" then return "http2"
    elseif _path_val == "HTTP_AGG" then return "http_agg"
    elseif _path_val == "HTTP_RED" then return "http_red"
    elseif _path_val == "INTEL" then return "intel"
    elseif _path_val == "KERBEROS" then return "kerberos"
    elseif _path_val == "NOTICE" then return "notice"
    elseif _path_val == "RDP" then return "rdp"
    elseif _path_val == "SMB_FILES" then return "smb_files"
    elseif _path_val == "SMB_MAPPING" then return "smb_mapping"
    elseif _path_val == "SOFTWARE" then return "software"
    elseif _path_val == "SSH" then return "ssh"
    elseif _path_val == "SSL" then return "ssl"
    elseif _path_val == "SSL_AGG" then return "ssl_agg"
    elseif _path_val == "SSL_RED" then return "ssl_red"
    elseif _path_val == "SURICATA_CORELIGHT" then return "suricata_corelight"
    elseif _path_val == "VPN" then return "vpn"
    elseif _path_val == "CORELIGHT_METRICS_IFACE" then return "corelight_metrics_iface"
    elseif _path_val == "CORELIGHT_METRICS_MEMORY" then return "corelight_metrics_memory"
    elseif _path_val == "CORELIGHT_METRICS_BRO" then return "corelight_metrics_bro"
    elseif _path_val == "CORELIGHT_METRICS_SYSTEM" then return "corelight_metrics_system"
    elseif _path_val == "CORELIGHT_METRICS_ZEEK_DOCTOR" then return "corelight_metrics_zeek_doctor"
    elseif _path_val == "X509" then return "x509"
    elseif _path_val == "ANOMALY" then return "anomaly"
    elseif _path_val == "NET_PERF" then return "net_perf"
    elseif _path_val == "YARA_CORELIGHT" then return "yara_corelight"
    elseif _path_val == "CORELIGHT_ML_RESULTS" then return "corelight_ml_results"
    end
    return ""
end

-- =========================================================
-- processEvent (top-level dispatcher)
-- =========================================================

function processEvent(event)
    if type(event) ~= "table" then return {} end
    no_nulls(event)
    local event_type = findEventType(event)
    local result = nil
    if event_type == "asset_classification" then
        result = processAssetClassificationEvents(event)
    elseif event_type == "conn" then
        result = processConnEvents(event)
    elseif event_type == "conn_agg" then
        result = processConnAggEvents(event)
    elseif event_type == "conn_long" then
        result = processConnLongEvents(event)
    elseif event_type == "conn_red" then
        result = processConnRedEvents(event)
    elseif event_type == "corelight_metrics_disk" then
        result = processCorelightMetricsDiskEvents(event)
    elseif event_type == "dns" then
        result = processDnsEvents(event)
    elseif event_type == "dns_agg" then
        result = processDnsAggEvents(event)
    elseif event_type == "dns_red" then
        result = processDnsRedEvents(event)
    elseif event_type == "etc_viz" then
        result = processEtcVizEvents(event)
    elseif event_type == "files" then
        result = processFilesEvents(event)
    elseif event_type == "files_agg" then
        result = processFilesAggEvents(event)
    elseif event_type == "files_red" then
        result = processFilesRedEvents(event)
    elseif event_type == "ftp" then
        result = processFtpEvents(event)
    elseif event_type == "http" then
        result = processHttpEvents(event)
    elseif event_type == "http2" then
        result = processHttp2Events(event)
    elseif event_type == "http_agg" then
        result = processHttpAggEvents(event)
    elseif event_type == "http_red" then
        result = processHttpRedEvents(event)
    elseif event_type == "intel" then
        result = processIntelEvents(event)
    elseif event_type == "kerberos" then
        result = processKerberosEvents(event)
    elseif event_type == "notice" then
        result = processNoticeEvents(event)
    elseif event_type == "rdp" then
        result = processRdpEvents(event)
    elseif event_type == "smb_files" then
        result = processSmbFilesEvents(event)
    elseif event_type == "smb_mapping" then
        result = processSmbMappingEvents(event)
    elseif event_type == "software" then
        result = processSoftwareEvents(event)
    elseif event_type == "ssh" then
        result = processSshEvents(event)
    elseif event_type == "ssl" then
        result = processSslEvents(event)
    elseif event_type == "ssl_agg" then
        result = processSslAggEvents(event)
    elseif event_type == "ssl_red" then
        result = processSslRedEvents(event)
    elseif event_type == "suricata_corelight" then
        result = processSuricataCorelightEvents(event)
    elseif event_type == "vpn" then
        result = processVpnEvents(event)
    elseif event_type == "corelight_metrics_iface" then
        result = processCorelightMetricsIfaceEvents(event)
    elseif event_type == "corelight_metrics_memory" then
        result = processCorelightMetricsMemoryEvents(event)
    elseif event_type == "corelight_metrics_bro" then
        result = processCorelightMetricsBroEvents(event)
    elseif event_type == "corelight_metrics_system" then
        result = processCorelightMetricsSystemEvents(event)
    elseif event_type == "corelight_metrics_zeek_doctor" then
        result = processCorelightMetricsZeekDoctorEvents(event)
    elseif event_type == "x509" then
        result = processX509Events(event)
    elseif event_type == "anomaly" then
        result = processAnomalyEvents(event)
    elseif event_type == "net_perf" then
        result = processNetPerfEvents(event)
    elseif event_type == "yara_corelight" then
        result = processYaraCorelightEvents(event)
    elseif event_type == "corelight_ml_results" then
        result = processCorelightMlResultsEvents(event)
    end
    if result == nil then
        result = processUnknownEvents(event)
    end
    return result
end
