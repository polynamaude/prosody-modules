local jid = require "util.jid";
local time = os.time;
local log_ip = module:get_option_boolean("lastlog_ip_address", false);

local store;
if module.host ~= "*" then -- workaround for prosodyctl loading into global context
	store = module:open_store(nil, "map");
end

module:hook("authentication-success", function(event)
	local session = event.session;
	if session.username then
		store:set(session.username, "login", {
			timestamp = time(),
			ip = log_ip and session and session.ip or nil,
		});
	end
end);

module:hook("resource-unbind", function(event)
	local session = event.session;
	if session.username then
		store:set(session.username, "logout", {
			timestamp = time(),
			ip = log_ip and session and session.ip or nil,
		});
	end
end);

module:hook("user-registered", function(event)
	local session = event.session;
	store:set(event.username, "registered", {
		timestamp = time(),
		ip = log_ip and session and session.ip or nil,
	});
end);


if module:get_host_type() == "component" then
	module:hook("message/bare", function(event)
		local room = jid.split(event.stanza.attr.to);
		if room then
			store:set(room, module.host, "message", {
				timestamp = time(),
			});
		end
	end);
end

function module.command(arg)
	if not arg[1] or arg[1] == "--help" then
		require"util.prosodyctl".show_usage([[mod_lastlog <user@host>]], [[Show when user last logged in or out]]);
		return 1;
	end
	local user, host = jid.prepped_split(table.remove(arg, 1));
	require"core.storagemanager".initialize_host(host);
	store = module:context(host):open_store();
	local lastlog = store:get(user);
	if lastlog then
		for event, data in pairs(lastlog) do
			print(("Last %s: %s"):format(event,
				data.timestamp and os.date("%Y-%m-%d %H:%M:%S", data.timestamp) or "<unknown>"));
			if data.ip then
				print("IP address: "..data.ip);
			end
		end
	else
		print("No record found");
		return 1;
	end
	return 0;
end
