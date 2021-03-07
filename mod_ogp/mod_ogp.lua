local mod_muc = module:depends("muc")
local http = require "net.http"
local st = require "util.stanza"
local url_pattern = [[https?://%S+]]
local domain_pattern = '^%w+://([^/]+)'
local xmlns_fasten = "urn:xmpp:fasten:0"
local xmlns_xhtml = "http://www.w3.org/1999/xhtml"
local whitelist = module:get_option_set("ogp_domain_whitelist", {})


local function is_whitelisted(url)
	if whitelist:empty() then
		return true
	end
	local domain = url:match(domain_pattern)
	if whitelist:contains(domain) then
		return true;
	end
	return false
end


local function fetch_ogp_data(room, url, origin_id)
	if not url or not is_whitelisted(url) then
		return;
	end

	http.request(
		url,
		nil,
		function(response_body, response_code, _)
			if response_code ~= 200 then
				return
			end

			local to = room.jid
			local from = room and room.jid or module.host
			local fastening = st.message({to = to, from = from, type = 'groupchat'}):tag("apply-to", {xmlns = xmlns_fasten, id = origin_id})
			local found_metadata = false
			local message_body = ""

			local meta_pattern = [[<meta (.-)/?>]]
			for match in response_body:gmatch(meta_pattern) do
				local property = match:match([[property=%s*["']?(og:.-)["']?%s]])
				if not property then
					property = match:match([[property=["']?(og:.-)["']$]])
				end

				local content = match:match([[content=%s*["'](.-)["']%s]])
				if not content then
					content = match:match([[content=["']?(.-)["']$]])
				end
				if not content then
					content = match:match([[content=(.-) property]])
				end
				if not content then
					content = match:match([[content=(.-)$]])
				end

				if property and content then
					module:log("info", property .. "\t" .. content)
					fastening:tag(
						"meta",
						{
							xmlns = xmlns_xhtml,
							property = property,
							content = content
						}
					):up()
					found_metadata = true
					message_body = message_body .. property .. "\t" .. content .. "\n"
				end
			end

			if found_metadata then
				mod_muc.get_room_from_jid(room.jid):broadcast_message(fastening)
			end
			module:log("info", tostring(fastening))
		end
	)
end

local function ogp_handler(event)
	local room, stanza = event.room, st.clone(event.stanza)
	local body = stanza:get_child_text("body")

	if not body then return; end

	local origin_id = stanza:find("{urn:xmpp:sid:0}origin-id@id")
	if not origin_id then return; end

	for url in body:gmatch(url_pattern) do
		fetch_ogp_data(room, url, origin_id);
	end
end

module:hook("muc-occupant-groupchat", ogp_handler)


module:hook("muc-message-is-historic", function (event)
	local fastening = event.stanza:get_child('apply-to', xmlns_fasten)
	if fastening and fastening:get_child('meta', xmlns_xhtml) then
		return true
	end
end);
