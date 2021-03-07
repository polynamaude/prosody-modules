-- RESTful API
--
-- Copyright (c) 2019-2020 Kim Alvefur
--
-- This file is MIT/X11 licensed.

local encodings = require "util.encodings";
local base64 = encodings.base64;
local errors = require "util.error";
local http = require "net.http";
local id = require "util.id";
local jid = require "util.jid";
local json = require "util.json";
local st = require "util.stanza";
local um = require "core.usermanager";
local xml = require "util.xml";
local have_cbor, cbor = pcall(require, "cbor");

local jsonmap = module:require"jsonmap";

local tokens = module:depends("tokenauth");

local auth_mechanisms = module:get_option_set("rest_auth_mechanisms", { "Basic", "Bearer" });

local www_authenticate_header;
do
	local header, realm = {}, module.host.."/"..module.name;
	for mech in auth_mechanisms do
		header[#header+1] = ("%s realm=%q"):format(mech, realm);
	end
	www_authenticate_header = table.concat(header, ", ");
end

-- Bearer token
local function check_credentials(request)
	local auth_type, auth_data = string.match(request.headers.authorization, "^(%S+)%s(.+)$");
	if not (auth_type and auth_data) or not auth_mechanisms:contains(auth_type) then
		return false;
	end

	if auth_type == "Basic" then
		local creds = base64.decode(auth_data);
		if not creds then return false; end
		local username, password = string.match(creds, "^([^:]+):(.*)$");
		if not username then return false; end
		username, password = encodings.stringprep.nodeprep(username), encodings.stringprep.saslprep(password);
		if not username then return false; end
		if not um.test_password(username, module.host, password) then
			return false;
		end
		return { username = username, host = module.host };
	elseif auth_type == "Bearer" then
		local token_info = tokens.get_token_info(auth_data);
		if not token_info or not token_info.session then
			return false;
		end
		return token_info.session;
	end
	return nil;
end

-- (table, string) -> table
local function amend_from_path(data, path)
	local st_kind, st_type, st_to = path:match("^([mpi]%w+)/(%w+)/(.*)$");
	if not st_kind then return; end
	if st_kind == "iq" and st_type ~= "get" and st_type ~= "set" then
		-- GET /iq/disco/jid
		data.kind = "iq";
		data.type = "get";
		data[st_type] = true;
	else
		data.kind = st_kind;
		data.type = st_type;
	end
	if st_to and st_to ~= "" then
		data.to = st_to;
	end
	return data;
end

local function parse(mimetype, data, path) --> Stanza, error enum
	mimetype = mimetype and mimetype:match("^[^; ]*");
	if mimetype == "application/xmpp+xml" then
		return xml.parse(data);
	elseif mimetype == "application/json" then
		local parsed, err = json.decode(data);
		if not parsed then
			return parsed, err;
		end
		if path and not amend_from_path(parsed, path) then return nil, "invalid-path"; end
		return jsonmap.json2st(parsed);
	elseif mimetype == "application/cbor" and have_cbor then
		local parsed, err = cbor.decode(data);
		if not parsed then
			return parsed, err;
		end
		return jsonmap.json2st(parsed);
	elseif mimetype == "application/x-www-form-urlencoded"then
		local parsed = http.formdecode(data);
		if type(parsed) == "string" then
			return parse("text/plain", parsed);
		end
		for i = #parsed, 1, -1 do
			parsed[i] = nil;
		end
		if path and not amend_from_path(parsed, path) then return nil, "invalid-path"; end
		return jsonmap.json2st(parsed);
	elseif mimetype == "text/plain" then
		if not path then
			return st.message({ type = "chat" }, data);
		end
		local parsed = {};
		if not amend_from_path(parsed, path) then return nil, "invalid-path"; end
		if parsed.kind == "message" then
			parsed.body = data;
		elseif parsed.kind == "presence" then
			parsed.show = data;
		else
			return nil, "invalid-path";
		end
		return jsonmap.json2st(parsed);
	elseif not mimetype and path then
		local parsed = amend_from_path({}, path);
		if not parsed then return nil, "invalid-path"; end
		return jsonmap.json2st(parsed);
	end
	return nil, "unknown-payload-type";
end

local function decide_type(accept, supported_types)
	-- assumes the accept header is sorted
	local ret = supported_types[1];
	for i = 2, #supported_types do
		if (accept:find(supported_types[i], 1, true) or 1000) < (accept:find(ret, 1, true) or 1000) then
			ret = supported_types[i];
		end
	end
	return ret;
end

local supported_inputs = {
	"application/xmpp+xml",
	"application/json",
	"application/x-www-form-urlencoded",
	"text/plain",
};

local supported_outputs = {
	"application/xmpp+xml",
	"application/json",
	"application/x-www-form-urlencoded",
};

if have_cbor then
	table.insert(supported_inputs, "application/cbor");
	table.insert(supported_outputs, "application/cbor");
end

-- Only { string : string } can be form-encoded, discard the rest
-- (jsonmap also discards anything unknown or unsupported)
local function flatten(t)
	local form = {};
	for k, v in pairs(t) do
		if type(v) == "string" then
			form[k] = v;
		elseif type(v) == "number" then
			form[k] = tostring(v);
		elseif v == true then
			form[k] = "";
		end
	end
	return form;
end

local function encode(type, s)
	if type == "application/json" then
		return json.encode(jsonmap.st2json(s));
	elseif type == "application/x-www-form-urlencoded" then
		return http.formencode(flatten(jsonmap.st2json(s)));
	elseif type == "application/cbor" then
		return cbor.encode(jsonmap.st2json(s));
	elseif type == "text/plain" then
		return s:get_child_text("body") or "";
	end
	return tostring(s);
end

local post_errors = errors.init("mod_rest", {
	noauthz = { code = 401, type = "auth", condition = "not-authorized", text = "No credentials provided" },
	unauthz = { code = 403, type = "auth", condition = "not-authorized", text = "Credentials not accepted" },
	parse = { code = 400, condition = "not-well-formed", text = "Failed to parse payload", },
	xmlns = { code = 422, condition = "invalid-namespace", text = "'xmlns' attribute must be empty", },
	name = { code = 422, condition = "unsupported-stanza-type", text = "Invalid stanza, must be 'message', 'presence' or 'iq'.", },
	to = { code = 422, condition = "improper-addressing", text = "Invalid destination JID", },
	from = { code = 422, condition = "invalid-from", text = "Invalid source JID", },
	post_auth = { code = 403, condition = "not-authorized", text = "Not authorized to send stanza with requested 'from'", },
	iq_type = { code = 422, condition = "invalid-xml", text = "'iq' stanza must be of type 'get' or 'set'", },
	iq_tags = { code = 422, condition = "bad-format", text = "'iq' stanza must have exactly one child tag", },
	mediatype = { code = 415, condition = "bad-format", text = "Unsupported media type" },
});

-- GET → iq-get
local function parse_request(request, path)
	if path and request.method == "GET" then
		-- e.g. /verison/{to}
		return parse(nil, nil, "iq/"..path);
	else
		return parse(request.headers.content_type, request.body, path);
	end
end

local function handle_request(event, path)
	local request, response = event.request, event.response;
	local from;
	local origin;

	if not request.headers.authorization then
		response.headers.www_authenticate = www_authenticate_header;
		return post_errors.new("noauthz");
	else
		origin = check_credentials(request);
		if not origin then
			return post_errors.new("unauthz");
		end
		from = jid.join(origin.username, origin.host, origin.resource);
	end
	local payload, err = parse_request(request, path);
	if not payload then
		-- parse fail
		local ctx = { error = err, type = request.headers.content_type, data = request.body, };
		if err == "unknown-payload-type" then
			return post_errors.new("mediatype", ctx);
		end
		return post_errors.new("parse", ctx);
	end

	if payload.attr.xmlns then
		return post_errors.new("xmlns");
	elseif payload.name ~= "message" and payload.name ~= "presence" and payload.name ~= "iq" then
		return post_errors.new("name");
	end

	local to = jid.prep(payload.attr.to);
	if not to then
		return post_errors.new("to");
	end

	if payload.attr.from then
		local requested_from = jid.prep(payload.attr.from);
		if not requested_from then
			return post_errors.new("from");
		end
		if jid.compare(requested_from, from) then
			from = requested_from;
		else
			return post_errors.new("from_auth");
		end
	end

	payload.attr = {
		from = from,
		to = to,
		id = payload.attr.id or id.medium(),
		type = payload.attr.type,
		["xml:lang"] = payload.attr["xml:lang"],
	};

	module:log("debug", "Received[rest]: %s", payload:top_tag());
	local send_type = decide_type((request.headers.accept or "") ..",".. (request.headers.content_type or ""), supported_outputs)
	if payload.name == "iq" then
		function origin.send(stanza)
			module:send(stanza);
		end

		if payload.attr.type ~= "get" and payload.attr.type ~= "set" then
			return post_errors.new("iq_type");
		elseif #payload.tags ~= 1 then
			return post_errors.new("iq_tags");
		end

		return module:send_iq(payload, origin):next(
			function (result)
				module:log("debug", "Sending[rest]: %s", result.stanza:top_tag());
				response.headers.content_type = send_type;
				return encode(send_type, result.stanza);
			end,
			function (error)
				if not errors.is_err(error) then
					module:log("error", "Uncaught native error: %s", error);
					return select(2, errors.coerce(nil, error));
				elseif error.context and error.context.stanza then
					response.headers.content_type = send_type;
					module:log("debug", "Sending[rest]: %s", error.context.stanza:top_tag());
					return encode(send_type, error.context.stanza);
				else
					return error;
				end
			end);
	else
		function origin.send(stanza)
			module:log("debug", "Sending[rest]: %s", stanza:top_tag());
			response.headers.content_type = send_type;
			response:send(encode(send_type, stanza));
			return true;
		end

		module:send(payload, origin);
		return 202;
	end
end

local demo_handlers = {};
if module:get_option_path("rest_demo_resources", nil) then
	demo_handlers = module:require"apidemo";
end

-- Handle stanzas submitted via HTTP
module:depends("http");
module:provides("http", {
		route = {
			POST = handle_request;
			["POST /*"] = handle_request;
			["GET /*"] = handle_request;

			-- Only if api_demo_resources are set
			["GET /"] = demo_handlers.redirect;
			["GET /demo/"] = demo_handlers.main_page;
			["GET /demo/openapi.yaml"] = demo_handlers.schema;
			["GET /demo/*"] = demo_handlers.resources;
		};
	});

-- Forward stanzas from XMPP to HTTP and return any reply
local rest_url = module:get_option_string("rest_callback_url", nil);
if rest_url then
	local send_type = module:get_option_string("rest_callback_content_type", "application/xmpp+xml");
	if send_type == "json" then
		send_type = "application/json";
	end

	module:set_status("info", "Not yet connected");
	http.request(rest_url, {
			method = "OPTIONS",
		}, function (body, code, response)
			if code == 0 then
				return module:log_status("error", "Could not connect to callback URL %q: %s", rest_url, body);
			else
				module:set_status("info", "Connected");
			end
			if code == 200 and response.headers.accept then
				send_type = decide_type(response.headers.accept, supported_outputs);
				module:log("debug", "Set 'rest_callback_content_type' = %q based on Accept header", send_type);
			end
		end);

	local code2err = require "net.http.errors".registry;

	local function handle_stanza(event)
		local stanza, origin = event.stanza, event.origin;
		local reply_allowed = stanza.attr.type ~= "error";
		local reply_needed = reply_allowed and stanza.name == "iq";
		local receipt;

		if reply_allowed and stanza.name == "message" and stanza.attr.id and stanza:get_child("urn:xmpp:receipts", "request") then
			reply_needed = true;
			receipt = st.stanza("received", { xmlns = "urn:xmpp:receipts", id = stanza.id });
		end

		local request_body = encode(send_type, stanza);

		-- Keep only the top level element and let the rest be GC'd
		stanza = st.clone(stanza, true);

		module:log("debug", "Sending[rest]: %s", stanza:top_tag());
		http.request(rest_url, {
				body = request_body,
				headers = {
					["Content-Type"] = send_type,
					["Content-Language"] = stanza.attr["xml:lang"],
					Accept = table.concat(supported_inputs, ", ");
				},
			}):next(function (response)
				module:set_status("info", "Connected");
				local reply;

				local code, body = response.code, response.body;
				if not reply_allowed then
					return;
				elseif code == 202 or code == 204 then
					if not reply_needed then
						-- Delivered, no reply
						return;
					end
				else
					local parsed, err = parse(response.headers["content-type"], body);
					if not parsed then
						module:log("warn", "Failed parsing data from REST callback: %s, %q", err, body);
					elseif parsed.name ~= stanza.name then
						module:log("warn", "REST callback responded with the wrong stanza type, got %s but expected %s", parsed.name, stanza.name);
					else
						parsed.attr = {
							from = stanza.attr.to,
							to = stanza.attr.from,
							id = parsed.attr.id or id.medium();
							type = parsed.attr.type,
							["xml:lang"] = parsed.attr["xml:lang"],
						};
						if parsed.name == "message" and parsed.attr.type == "groupchat" then
							parsed.attr.to = jid.bare(stanza.attr.from);
						end
						if not stanza.attr.type and parsed:get_child("error") then
							parsed.attr.type = "error";
						end
						if parsed.attr.type == "error" then
							parsed.attr.id = stanza.attr.id;
						elseif parsed.name == "iq" then
							parsed.attr.id = stanza.attr.id;
							parsed.attr.type = "result";
						end
						reply = parsed;
					end
				end

				if not reply then
					local code_hundreds = code - (code % 100);
					if code_hundreds == 200 then
						reply = st.reply(stanza);
						if stanza.name ~= "iq" then
							reply.attr.id = id.medium();
						end
						-- TODO presence/status=body ?
					elseif code2err[code] then
						reply = st.error_reply(stanza, errors.new(code, nil, code2err));
					elseif code_hundreds == 400 then
						reply = st.error_reply(stanza, "modify", "bad-request", body);
					elseif code_hundreds == 500 then
						reply = st.error_reply(stanza, "cancel", "internal-server-error", body);
					else
						reply = st.error_reply(stanza, "cancel", "undefined-condition", body);
					end
				end

				if receipt then
					reply:add_direct_child(receipt);
				end

				module:log("debug", "Received[rest]: %s", reply:top_tag());

				origin.send(reply);
			end,
			function (err)
				module:log_status("error", "Could not connect to callback URL %q: %s", rest_url, err);
				origin.send(st.error_reply(stanza, "wait", "recipient-unavailable", err.text));
			end):catch(function (err)
				module:log("error", "Error[rest]: %s", err);
			end);

		return true;
	end

	if module:get_host_type() == "component" then
		module:hook("iq/bare", handle_stanza, -1);
		module:hook("message/bare", handle_stanza, -1);
		module:hook("presence/bare", handle_stanza, -1);
		module:hook("iq/full", handle_stanza, -1);
		module:hook("message/full", handle_stanza, -1);
		module:hook("presence/full", handle_stanza, -1);
		module:hook("iq/host", handle_stanza, -1);
		module:hook("message/host", handle_stanza, -1);
		module:hook("presence/host", handle_stanza, -1);
	else
		-- Don't override everything on normal VirtualHosts
		module:hook("iq/host", handle_stanza, -1);
		module:hook("message/host", handle_stanza, -1);
		module:hook("presence/host", handle_stanza, -1);
	end
end

local supported_errors = {
	"text/html",
	"application/xmpp+xml",
	"application/json",
};

local http_server = require "net.http.server";
module:hook_object_event(http_server, "http-error", function (event)
	local request, response = event.request, event.response;
	local response_as = decide_type(request and request.headers.accept or "", supported_errors);
	if response_as == "application/xmpp+xml" then
		if response then
			response.headers.content_type = "application/xmpp+xml";
		end
		local stream_error = st.stanza("error", { xmlns = "http://etherx.jabber.org/streams" });
		if event.error then
			stream_error:tag(event.error.condition, {xmlns = 'urn:ietf:params:xml:ns:xmpp-streams' }):up();
			if event.error.text then
				stream_error:text_tag("text", event.error.text, {xmlns = 'urn:ietf:params:xml:ns:xmpp-streams' });
			end
		end
		return tostring(stream_error);
	elseif response_as == "application/json" then
		if response then
			response.headers.content_type = "application/json";
		end
		return json.encode({
				type = "error",
				error = event.error,
				code = event.code,
			});
	end
end, 1);
