# teltonika-wireshark
Teltonika wireshark dissector in LUA

# Usage
I'm a windows guy, so on windows you just copy the teltonika-dissector.lua to `~\AppData\Roaming\Wireshark\plugins` (`~` works on powershell, on CMD use whatever the home env variable is instead).

If wireshark is running you can reload it with `ctrl+shift+L`.

Wireshark LUA documentation is here https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html . VS code with LUA plugin works for code-highlighing. Maybe there is a way to do intellisense as well, if anyone finds any use for this and figures that out, please let me know.
