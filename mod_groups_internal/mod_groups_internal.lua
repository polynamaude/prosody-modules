local rostermanager = require"core.rostermanager";
local modulemanager = require"core.modulemanager";
local id = require "util.id";
local jid = require "util.jid";
local st = require "util.stanza";
local jid_join = jid.join;
local host = module.host;

local group_info_store = module:open_store("group_info");
local group_members_store = module:open_store("groups");
local group_memberships = module:open_store("groups", "map");

local muc_host_name = module:get_option("groups_muc_host", "groups."..host);
local muc_host = nil;

local is_contact_subscribed = rostermanager.is_contact_subscribed;

-- Make a *one-way* subscription. User will see when contact is online,
-- contact will not see when user is online.
local function subscribe(user, user_jid, contact, contact_jid)
	-- Update user's roster to say subscription request is pending...
	rostermanager.set_contact_pending_out(user, host, contact_jid);
	-- Update contact's roster to say subscription request is pending...
	rostermanager.set_contact_pending_in(contact, host, user_jid);
	-- Update contact's roster to say subscription request approved...
	rostermanager.subscribed(contact, host, user_jid);
	-- Update user's roster to say subscription request approved...
	rostermanager.process_inbound_subscription_approval(user, host, contact_jid);

	-- Push updates to both rosters
	rostermanager.roster_push(user, host, contact_jid);
	rostermanager.roster_push(contact, host, user_jid);
end

local function user_groups(username)
	return pairs(group_memberships:get_all(username) or {});
end

local function do_single_group_subscriptions(username, group_id)
	local members = group_members_store:get(group_id);
	if not members then return; end
	local user_jid = jid_join(username, host);
	for membername in pairs(members) do
		if membername ~= username then
			local member_jid = jid_join(membername, host);
			if not is_contact_subscribed(username, host, member_jid) then
				module:log("debug", "[group %s] Subscribing %s to %s", member_jid, user_jid);
				subscribe(membername, member_jid, username, user_jid);
			end
			if not is_contact_subscribed(membername, host, user_jid) then
				module:log("debug", "[group %s] Subscribing %s to %s", user_jid, member_jid);
				subscribe(username, user_jid, membername, member_jid);
			end
		end
	end
end

local function do_all_group_subscriptions_by_user(username)
	for group_id in user_groups(username) do
		do_single_group_subscriptions(username, group_id);
	end
end

local function do_all_group_subscriptions_by_group(group_id)
	local members = get_members(group_id)
	if not members then
		return
	end
	for membername in pairs(members) do
		do_single_group_subscriptions(membername, group_id);
	end
end

module:hook("resource-bind", function(event)
	module:log("debug", "Updating group subscriptions...");
	do_all_group_subscriptions_by_user(event.session.username);
end);

--luacheck: ignore 131
function create(group_info, create_muc, group_id)
	if not group_info.name then
		return nil, "group-name-required";
	end
	if group_id then
		if exists(group_id) then
			return nil, "conflict"
		end
	else
		group_id = id.short();
	end

	local muc_jid = nil
	local room = nil
	if create_muc then
		if not muc_host_name then
			module:log("error", "cannot create group with MUC: no MUC host configured")
			return nil, "service-unavailable"
		end
		if not muc_host then
			module:log("error", "cannot create group with MUC: MUC host %s not configured properly", muc_host_name)
			return nil, "internal-server-error"
		end

		muc_jid = jid.prep(id.short() .. "@" .. muc_host_name);
		room = muc_host.create_room(muc_jid)
		if not room then
			delete(group_id)
			return nil, "internal-server-error"
		end
		room:set_public(false)
		room:set_persistent(true)
		room:set_members_only(true)
		room:set_allow_member_invites(false)
		room:set_moderated(false)
		room:set_whois("anyone")
		room:set_name(group_info.name)
	end

	local ok = group_info_store:set(group_id, {
		name = group_info.name;
		muc_jid = muc_jid;
	});
	if not ok then
		if room then
			room:destroy()
		end
		return nil, "internal-server-error";
	end

	return group_id;
end

function get_info(group_id)
	return group_info_store:get(group_id);
end

function set_info(group_id, info)
	if not info then
		return nil, "bad-request"
	end

	if not info.name or #info.name == 0 then
		return nil, "bad-request"
	end

	-- TODO: we should probably prohibit changing/removing the MUC JID of
	-- an existing group.
	if info.muc_jid then
		room = muc_host.get_room_from_jid(info.muc_jid);
		room:set_name(info.name);
	end

	local ok = group_info_store:set(group_id, info);
	if not ok then
		return nil, "internal-server-error";
	end
	return true
end

function get_members(group_id)
	return group_members_store:get(group_id);
end

function exists(group_id)
	return not not get_info(group_id);
end

function get_user_groups(username)
	local groups = {};
	do
		local group_set = group_memberships:get_all(username);
		if group_set then
			for group_id in pairs(group_set) do
				table.insert(groups, group_id);
			end
		end
	end
	return groups;
end

function delete(group_id)
	if group_members_store:set(group_id, nil) then
		local group_info = get_info(group_id);
		if group_info and group_info.muc_jid then
			local room = muc_host.get_room_from_jid(group_info.muc_jid)
			if room then
				room:destroy()
			end
		end
		return group_info_store:set(group_id, nil);
	end
	return nil, "internal-server-error";
end

function add_member(group_id, username, delay_update)
	local group_info = group_info_store:get(group_id);
	if not group_info then
		return nil, "group-not-found";
	end
	if not group_memberships:set(group_id, username, {}) then
		return nil, "internal-server-error";
	end
	if group_info.muc_jid then
		local room = muc_host.get_room_from_jid(group_info.muc_jid);
		if room then
			local user_jid = username .. "@" .. host;
			room:set_affiliation(true, user_jid, "member");
			module:send(st.message(
				{ from = group_info.muc_jid, to = user_jid }
			):tag("x", {
				xmlns = "jabber:x:conference",
				jid = group_info.muc_jid
			}):up());
			module:log("debug", "set user %s to be member in %s and sent invite", username, group_info.muc_jid);
		else
			module:log("warn", "failed to update affiliation for %s in %s", username, group_info.muc_jid);
		end
	end
	module:fire_event(
		"group-user-added",
		{
			id = group_id,
			user = username,
			host = host,
			group_info = group_info,
		}
	)
	if not delay_update then
		do_all_group_subscriptions_by_group(group_id);
	end
	return true;
end

function remove_member(group_id, username)
	local group_info = group_info_store:get(group_id);
	if not group_info then
		return nil, "group-not-found";
	end
	if not group_memberships:set(group_id, username, nil) then
		return nil, "internal-server-error";
	end
	if group_info.muc_jid then
		local room = muc_host.get_room_from_jid(group_info.muc_jid);
		if room then
			local user_jid = username .. "@" .. host;
			room:set_affiliation(true, user_jid, nil);
		else
			module:log("warn", "failed to update affiliation for %s in %s", username, group_info.muc_jid);
		end
	end
	module:fire_event(
		"group-user-removed",
		{
			id = group_id,
			user = username,
			host = host,
			group_info = group_info,
		}
	)
	return true;
end

function sync(group_id)
	do_all_group_subscriptions_by_group(group_id);
end

function emit_member_events(group_id)
	local group_info, err = get_info(group_id)
	if group_info == nil then
		return false, err
	end

	for username in pairs(get_members(group_id)) do
		module:fire_event(
			"group-user-added",
			{
				id = group_id,
				user = username,
				host = host,
				group_info = group_info,
			}
		)
	end

	return true
end

-- Returns iterator over group ids
function groups()
	return group_info_store:users();
end

local function setup()
	if not muc_host_name then
		module:log("info", "MUC management disabled (groups_muc_host set to nil)");
		return;
	end

	local target_module = modulemanager.get_module(muc_host_name, "muc");
	if not target_module then
		module:log("error", "host %s is not a MUC host -- group management will not work correctly; check your groups_muc_host setting!", muc_host_name);
	else
		module:log("debug", "found MUC host at %s", muc_host_name);
		muc_host = target_module;
	end
end

if prosody.start_time then  -- server already started
	setup();
else
	module:hook_global("server-started", setup);
end
