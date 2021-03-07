local adhoc = require "util.adhoc";
local dataforms = require "util.dataforms";
local errors = require "util.error";
local hashes = require "util.hashes";
local id = require "util.id";
local jid = require "util.jid";
local base64 = require"util.encodings".base64;

local clients = module:open_store("oauth2_clients", "map");

local iteration_count = module:get_option_number("oauth2_client_iteration_count", 10000);
local pepper = module:get_option_string("oauth2_client_pepper", "");

local new_client = dataforms.new({
	title = "Create OAuth2 client";
	{var = "FORM_TYPE"; type = "hidden"; value = "urn:uuid:ff0d55ed-2187-4ee0-820a-ab633a911c14#create"};
	{name = "name"; type = "text-single"; label = "Client name"; required = true};
	{name = "description"; type = "text-multi"; label = "Description"};
	{name = "info_url"; type = "text-single"; label = "Informative URL"; desc = "Link to information about your client"; datatype = "xs:anyURI"};
	{
		name = "redirect_uri";
		type = "text-single";
		label = "Redirection URI";
		desc = "Where to redirect the user after authorizing.";
		datatype = "xs:anyURI";
		required = true;
	};
})

local client_created = dataforms.new({
	title = "New OAuth2 client created";
	instructions = "Save these details, they will not be shown again";
	{var = "FORM_TYPE"; type = "hidden"; value = "urn:uuid:ff0d55ed-2187-4ee0-820a-ab633a911c14#created"};
	{name = "client_id"; type = "text-single"; label = "Client ID"};
	{name = "client_secret"; type = "text-single"; label = "Client secret"};
})

local function create_client(client, formerr, data)
	if formerr then
		local errmsg = {"Error in form:"};
		for field, err in pairs(formerr) do table.insert(errmsg, field .. ": " .. err); end
		return {status = "error"; error = {message = table.concat(errmsg, "\n")}};
	end

	local creator = jid.split(data.from);
	local client_uid = id.short();
	local client_id = jid.join(creator, module.host, client_uid);
	local client_secret = id.long();
	local salt = id.medium();
	local i = iteration_count;

	client.secret_hash = base64.encode(hashes.pbkdf2_hmac_sha256(client_secret, salt .. pepper, i));
	client.iteration_count = i;
	client.salt = salt;

	local ok, err = errors.coerce(clients:set(creator, client_uid, client));
	module:log("info", "OAuth2 client %q created by %s", client_id, data.from);
	if not ok then return {status = "canceled"; error = {message = err}}; end

	return {status = "completed"; result = {layout = client_created; values = {client_id = client_id; client_secret = client_secret}}};
end

local handler = adhoc.new_simple_form(new_client, create_client);

module:provides("adhoc", module:require "adhoc".new(new_client.title, new_client[1].value, handler, "local_user"));

-- TODO list/manage/revoke clients
