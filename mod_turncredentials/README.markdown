# Introduction

[XEP-0215] implementation for [time-limited TURN
credentials](https://tools.ietf.org/html/draft-uberti-behave-turn-rest-00).

# Configuration

  Option                    Type     Default
  ------------------------- -------- ------------
  turncredentials\_secret   string   *required*
  turncredentials\_host     string   *required*
  turncredentials\_port     number   `3478`
  turncredentials\_ttl      number   `86400`

# Compatible TURN / STUN servers.

-   [coturn](https://github.com/coturn/coturn) - [setup guide][doc:coturn]
-   [restund](http://www.creytiv.com/restund.html)
-   [eturnal](https://eturnal.net/)

# Compatibility

Incompatible with [mod_extdisco](https://modules.prosody.im/mod_extdisco.html)
