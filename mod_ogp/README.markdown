# mod_ogp

This module adds [Open Graph Protocol](https://ogp.me) metadata to URLs sent inside a MUC.

With mod_ogp enabled, when a user sends a URL in a MUC (where the message has its `id` equal to its `origin-id`), the module calls the URL and parses the result for `<meta>` html tags that have any `og:...` properties.
If it finds any, it sends a [XEP-0422 fastening](https://xmpp.org/extensions/xep-0422.html) applied to the original message that looks like:

```xml
<message id="example" from="chatroom@muc.example.org" to="chatroom@muc.example.org">
<apply-to xmlns="urn:xmpp:fasten:0" id="origin-id-X">
<meta xmlns="http://www.w3.org/1999/xhtml" property="og:title" content="The Rock"/>
<meta xmlns="http://www.w3.org/1999/xhtml" property="og:url" content="https://www.imdb.com/title/tt0117500/"/>
<meta xmlns="http://www.w3.org/1999/xhtml" property="og:image" content="https://ia.media-imdb.com/images/rock.jpg"/>
</apply-to>
</message>
```

The module is intentionally simple in the sense that it is basically a transport for https://ogp.me/

Configuration
-------------

You can present a whitelist of domains for which OGP metadata will be fetched
via the `ogp_domain_whitelist` setting.

For example:

```lua
Component "muc.example.org" "muc"
  modules_enabled = { "ogp" }
  ogp_domain_whitelist = { "prosody.im" }
```
