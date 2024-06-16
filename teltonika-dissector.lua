--[[
  Very rudimentary wireshark LUA dissector for Teltonika protocols. Any update is more than welcome.
]]
teltonika_protocol = Proto("Teltonika", "Teltonika protocol")

teltonika_port = 5027

device_imei = ProtoField.string("teltonika.imei", "Device IMEI", base.ASCII)
preamble = ProtoField.bytes("teltonika.preamble", "Codec preamble", base.SPACE)
data_field_length = ProtoField.uint32("teltonika.data_field_length", "Data field length", base.DEC)
codec = ProtoField.bytes("teltonika.codec", "Codec type", base.NONE)
imei_accept = ProtoField.bytes("teltonika.imei_accept", "IMEI Accept", base.NONE)
packets_accepted = ProtoField.uint32("teltonika.packets_accepted", "Packets accepted", base.DEC)
ping = ProtoField.bytes("teltonika.ping", "Device ping", base.SPACE)

--[[
if gui_enabled() then
    can_log = true
    win = TextWindow.new("Log")
    win:add_button("Clear", function() win:clear() end)
    win:set_atclose(function() can_log = false end)
end
]]

teltonika_protocol.fields = { 
    preamble, 
    device_imei, 
    data_field_length, 
    codec,
    imei_accept,
    ping
 }

function teltonika_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = teltonika_protocol.name

    local subtree = tree:add(teltonika_protocol, buffer(), "Teltonika data")

    if (pinfo.dst_port == teltonika_port) then
        if (buffer(0,1):uint() == 0x00) and (buffer(1,1):uint() == 0x0F) then
            subtree:add_le(device_imei, buffer(2, 15))
        elseif (buffer(0,1):uint() == 0xFF)  then
            subtree:add_le(ping, buffer(0,1))
        else
            subtree:add_le(preamble, buffer(0, 4))
            subtree:add_le(data_field_length, buffer(4, 4):uint())
            subtree:add_le(codec, buffer(8,1))
        end
    elseif (pinfo.src_port == teltonika_port) then
        if (length == 1) then
            subtree:add_le(imei_accept, buffer(0, 1))
        else
            subtree:add_le(packets_accepted, buffer(0, 4):uint())
        end
    end
end

local tcp_port = DissectorTable.get("tcp.port")
local udp_port = DissectorTable.get("udp.port")
tcp_port:add(teltonika_port, teltonika_protocol)
udp_port:add(teltonika_port, teltonika_protocol)
