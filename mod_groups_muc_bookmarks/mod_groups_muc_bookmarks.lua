local jid_split = require "util.jid".split;

local st = require "util.stanza";

local mod_groups = module:depends("groups_internal")
local mod_pep = module:depends("pep")

local PUBSUB_NODE_XEP0048 = "storage:bookmarks";
local XMLNS_XEP0048 = "storage:bookmarks";
local XMLNS_XEP0060 = "http://jabber.org/protocol/pubsub";

local default_options = {
	["persist_items"] = true;
	["access_model"] = "whitelist";
};

local function get_current_bookmarks(jid, service)
	local ok, id, item = service:get_last_item(PUBSUB_NODE_XEP0048, jid)
	if not ok or id == nil then
		if id == "item-not-found" or id == nil then
			-- return empty
			return st.stanza("storage", { xmlns = XMLNS_XEP0048 });
		end
		return nil, result
	end
	-- first item is the actual storage element
	local hit = item:get_child("storage", XMLNS_XEP0048);
	if not hit then
		return nil, "internal-server-error"
	end
	return hit
end

local function update_bookmarks(jid, service, storage)
	local item = st.stanza("item", { xmlns = XMLNS_XEP0060, id = "current" }):add_child(storage)
	module:log("debug", "updating bookmarks with %q", item)
	local ok, err = service:publish(
		PUBSUB_NODE_XEP0048,
		jid,
		"current",
		item,
		default_options
	)
	if not ok then
		module:log("error", "failed to update bookmarks: %s", err)
	end
end

local function find_matching_bookmark(storage, room)
	for node in storage:childtags("conference") do
		if node.attr.jid == room then
			return node
		end
	end
	return nil
end

local function inject_bookmark(jid, room, autojoin, name)
	local pep_service = mod_pep.get_pep_service(jid_split(jid))

	autojoin = autojoin or false and true
	local current = get_current_bookmarks(jid, pep_service)
	local existing = find_matching_bookmark(current, room)
	if existing then
		if autojoin ~= nil then
			existing.attr.autojoin = autojoin and "true" or "false"
		end
		if name ~= nil then
			-- do not change already configured names
			if not existing.attr.name then
				existing.attr.name = name
			end
		end
		done = true
		module:log("debug", "found existing matching bookmark, updated")
	else
		module:log("debug", "no existing bookmark found, adding new")
		current:tag("conference", {
			name = name,
			autojoin = autojoin and "true" or "false",
			jid = room,
			xmlns = XMLNS_XEP0048,
		})
	end

	update_bookmarks(jid, pep_service, current)
end

local function remove_bookmark(jid, room, autojoin, name)
	local pep_service = mod_pep.get_pep_service(jid_split(jid))

	autojoin = autojoin or false and true
	local current = get_current_bookmarks(jid, pep_service)
	current:maptags(function (node)
		if node.attr.xmlns and node.attr.xmlns ~= XMLNS_XEP0048 then
			return node
		end
		if node.name ~= "conference" then
			return node
		end
		if node.attr.jid == room then
			-- remove matching bookmark
			return nil
		end
		return node
	end)

	update_bookmarks(jid, pep_service, current)
end

local function handle_user_added(event)
	if not event.group_info.muc_jid then
		module:log("debug", "ignoring user added event on group %s because it has no MUC", event.id)
		return
	end
	local jid = event.user .. "@" .. event.host
	inject_bookmark(jid, event.group_info.muc_jid, true, event.group_info.name)
end

local function handle_user_removed(event)
	if not event.group_info.muc_jid then
		module:log("debug", "ignoring user removed event on group %s because it has no MUC", event.id)
		return
	end
	-- Removing the bookmark is fine as the user just lost any privilege to
	-- be in the MUC (as group MUCs are members-only).
	local jid = event.user .. "@" .. event.host
	remove_bookmark(jid, event.group_info.muc_jid, true, event.group_info.name)
end

module:hook("group-user-added", handle_user_added)
module:hook("group-user-removed", handle_user_removed)
