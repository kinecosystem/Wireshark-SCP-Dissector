local basexx = dofile("plugins/scp/basexx.lua")

readInt = function (tvbuf, offset)
  return tvbuf:range(offset, 4):int(), offset + 4
end

readUInt32 = function (tvbuf, offset)
  return tvbuf:range(offset, 4):uint(), offset + 4
end

readInt64 = function (tvbuf, offset)
  return tvbuf:range(offset, 8):int64(), offset + 8
end

readUInt64 = function (tvbuf, offset)
  return tvbuf:range(offset, 8):uint64(), offset + 8
end

publicKey = function(bytes)
  bytes = string.char(0x30) .. bytes
  local l, h = crc(bytes)
  return basexx.to_base32(bytes .. string.char(l) .. string.char(h))
end
