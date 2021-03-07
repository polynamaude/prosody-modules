
local _M = {};

local api_demo = module:get_option_path("rest_demo_resources", nil);
local http_files = require "net.http.files";

local mime_map = module:shared("/*/http_files/mime").types or {css = "text/css"; js = "application/javascript"};
_M.resources = http_files.serve({
		path = api_demo;
		mime_map = mime_map;
	});

local index do
	local f = assert(io.open(api_demo.."/index.html"), "'api_demo_resources' should point to the 'dist' directory");
	index = f:read("*a");
	f:close();

	-- SUCH HACK, VERY GSUB, WOW!
	index = index:gsub("(%s?url%s*:%s*)%b\"\"", string.format("%%1%q", module:http_url().."/demo/openapi.yaml"), 1);
end

do
	local f = module:load_resource("openapi.yaml");
	_M.schema = {
		headers = {
			content_type = "text/x-yaml";
		};
		body = f:read("*a");
	}
	f:close();
end

_M.redirect = {
	status_code = 303;
	headers = {
		location = module:http_url().."/demo/";
	};
};

_M.main_page = {
	headers = {
		content_type = "text/html";
	};
	body = index;
}

return _M
