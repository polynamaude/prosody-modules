local st = require "util.stanza";

module:add_item("muc-registration-field", {
	name = "{http://tigase.org/protocol/muc}offline";
	type = "boolean";
	label = "Receive messages while not connected to the room";
	value = false;
});

module:hook("muc-registration-submitted", function (event)
	local deliver_offline = event.submitted_data["{http://tigase.org/protocol/muc}offline"] or nil;
	event.affiliation_data.offline_delivery = deliver_offline;
end);

module:hook("muc-add-history", function (event)
	module:log("debug", "Broadcasting message to offline occupants...");
	local sent = 0;
	local room = event.room;
	for jid, affiliation, data in room:each_affiliation() do --luacheck: ignore 213/affiliation
		local reserved_nickname = data and data.reserved_nickname;
		module:log("debug", "Affiliated: %s, %s: %s", jid, reserved_nickname, data and data.offline_delivery);
		if reserved_nickname and data.offline_delivery then
			local is_absent = not room:get_occupant_by_nick(room.jid.."/"..reserved_nickname);
			if is_absent then
				local msg = st.clone(event.stanza);
				msg.attr.to = jid;
				module:send(msg);
				sent = sent + 1;
			end
		end
	end
	if sent > 0 then
		module:log("debug", "Sent message to %d offline occupants", sent);
	end
end);
