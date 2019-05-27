dofile("plugins/scp/bit.lua")
dofile("plugins/scp/crc.lua")
dofile("plugins/scp/helpers.lua")

local scp_proto = Proto("scp", "Stellar Concensus Protocol")
local envelope_proto = Proto("envelope", "Envelope")
local statement_proto = Proto("statement", "Statement")
local nomination_proto = Proto("nominate", "Nominate")
local prepare_proto = Proto("prepare", "Prepare")
local confirm_proto = Proto("confirm", "Confirm")
local ballot_proto = Proto("ballot", "Ballot")
local externalize_proto = Proto("externalize", "Externalize")
local transaction_proto = Proto("tx", "Tx")
local operation_proto = Proto("op", "Operation")

-- register the ProtoFields

dofile("plugins/scp/headers.lua")
scp_proto.fields = hdr_fields
envelope_proto.fields = env_hdr_fields
statement_proto.fields = stmt_hdr_fields
nomination_proto.fields = nom_hdr_fields
prepare_proto.fields = prep_hdr_fields
ballot_proto.fields = blt_hdr_fields
confirm_proto.fields = cfrm_hdr_fields
externalize_proto.fields = ext_hdr_fields
transaction_proto.fields = tx_hdr_fields
operation_proto.fields = op_hdr_fields

function scp_proto.dissector(tvbuf, pktinfo, root)
  -- get the length of the packet buffer (Tvb).
  local pktlen = tvbuf:len()

  local bytes_consumed = 0

  -- we do this in a while loop, because there could be multiple SCP messages
  -- inside a single TCP segment, and thus in the same tvbuf - but our
  -- scp_proto.dissector() will only be called once per TCP segment, so we
  -- need to do this loop to dissect each SCP message in it
  while bytes_consumed < pktlen do

      -- We're going to call our "dissect()" function, which is defined
      -- later in this script file. The dissect() function returns the
      -- length of the SCP message it dissected as a positive number, or if
      -- it's a negative number then it's the number of additional bytes it
      -- needs if the Tvb doesn't have them all. If it returns a 0, it's a
      -- dissection error.
      local result = dissectSCP(tvbuf, pktinfo, root, bytes_consumed)

      if result > 0 then
          -- we successfully processed an SCP message, of 'result' length
          bytes_consumed = bytes_consumed + result
          -- go again on another while loop
      elseif result == 0 then
          -- If the result is 0, then it means we hit an error of some kind,
          -- so return 0. Returning 0 tells Wireshark this packet is not for
          -- us, and it will try heuristic dissectors or the plain "data"
          -- one, which is what should happen in this case.
          return 0
      else
          -- we need more bytes, so set the desegment_offset to what we
          -- already consumed, and the desegment_len to how many more
          -- are needed
          pktinfo.desegment_offset = bytes_consumed

          -- invert the negative result so it's a positive number
          result = -result

          pktinfo.desegment_len = result

          -- even though we need more bytes, this packet is for us, so we
          -- tell wireshark all of its bytes are for us by returning the
          -- number of Tvb bytes we "successfully processed", namely the
          -- length of the Tvb
          return pktlen
      end
  end

  -- In a TCP dissector, you can either return nothing, or return the number of
  -- bytes of the tvbuf that belong to this protocol, which is what we do here.
  -- Do NOT return the number 0, or else Wireshark will interpret that to mean
  -- this packet did not belong to your protocol, and will try to dissect it
  -- with other protocol dissectors (such as heuristic ones)
  return bytes_consumed
end

local message_types = {
  ERROR_MSG = 0,
  AUTH = 2,
  DONT_HAVE = 3,

  GET_PEERS = 4,
  PEERS = 5,

  GET_TX_SET = 6,
  TX_SET = 7,

  TRANSACTION = 8,

  GET_SCP_QUORUMSET = 9,
  SCP_QUORUMSET = 10,
  SCP_MESSAGE = 11,
  GET_SCP_STATE = 12,

  HELLO = 13
}

local statement_types = {
  SCP_ST_PREPARE = 0,
  SCP_ST_CONFIRM = 1,
  SCP_ST_EXTERNALIZE = 2,
  SCP_ST_NOMINATE = 3
}

local message_types_funcs = {}
local statement_types_funcs = {}

dissectSCP = function (tvbuf, pktinfo, root, offset)
  local length_val, length_tvbr = checkScpLength(tvbuf, offset)

  if length_val <= 0 then
      return length_val
  end

  offset = offset + 4

  -- if we got here, then we have a whole message in the Tvb buffer
  -- so let's finish dissecting it...

  -- set the protocol column to show our protocol name
  pktinfo.cols.protocol:set("SCP")

  -- set the INFO column too, but only if we haven't already set it before
  -- for this frame/packet, because this function can be called multiple
  -- times per packet/Tvb
  if string.find(tostring(pktinfo.cols.info), "^SCP") == nil then
      pktinfo.cols.info:set("SCP")
  end

  -- We start by adding our protocol to the dissection display tree.
  local tree = root:add(scp_proto, tvbuf:range(offset, length_val))

  offset = offset + 4 -- discriminant

  tree:add(hdr_fields.sequence, tvbuf:range(offset, 8))
  offset = offset + 8

  type, offset = readInt(tvbuf, offset)

  local type_string
  for name, val in pairs(message_types) do
    if val == type then type_string = name end
  end

  tree:append_text(" - " .. type_string)

  -- if 1 then  return offset end

  offset = message_types_funcs[type](tvbuf, offset, tree)

  tree:add(hdr_fields.hmac, tvbuf:range(offset, 32))
  offset = offset + 32

  if offset < length_val then
    tree:add(hdr_fields.msg, tvbuf:range(offset, length_val - offset))
  end

  return length_val + 4
end

-- message dissectors

dissectError = function() end

dissectSCPMessage = function(tvbuf, offset, root)
  local env_tree = root:add(envelope_proto, tvbuf:range(offset, tvbuf:len() - offset))
  tree = env_tree:add(statement_proto, tvbuf:range(offset, tvbuf:len() - offset))

  tree:add(stmt_hdr_fields.node_id, tvbuf:range(offset + 4, 32))
  tree:add(stmt_hdr_fields.node_id_s, publicKey(tvbuf:raw(offset + 4, 32))):set_generated(true)
  offset = offset + 36

  tree:add(stmt_hdr_fields.slot_idx, tvbuf:range(offset, 8))
  offset = offset + 8

  type, offset = readInt(tvbuf, offset)

  local type_string
  for name, val in pairs(statement_types) do
    if val == type then type_string = name end
  end

  tree:append_text(" - " .. type_string)

  offset = statement_types_funcs[type](tvbuf, offset, tree)

  sig_length, offset = readInt(tvbuf, offset)
  env_tree:add(env_hdr_fields.signature, tvbuf:range(offset, sig_length))
  offset = offset + sig_length

  return offset
end

dissectGetTxSet = function(tvbuf, offset, tree)
  tree:add(hdr_fields.tx_set_hash, tvbuf:range(offset, 32))
  offset = offset + 32

  return offset
end

dissectTxSet = function(tvbuf, offset, tree)
  tree:add(hdr_fields.prev_hash, tvbuf:range(offset, 32))
  offset = offset + 32

  tx_count, offset = readInt(tvbuf, offset)
  for _ = 1, tx_count do
    offset = dissectTx(tvbuf, offset, tree)
  end

  return offset
end

dissectTx = function(tvbuf, offset, root)
  local advance = function(v) offset = offset + v end

  local tree = root:add(transaction_proto, tvbuf:range(offset, tvbuf:len() - offset))

  tree:add(tx_hdr_fields.source, tvbuf:range(offset + 4, 32))
  tree:add(tx_hdr_fields.source_s, publicKey(tvbuf:raw(offset + 4, 32))):set_generated(true)
  advance(36)

  tree:add(tx_hdr_fields.fee, tvbuf:range(offset, 4))
  advance(4)

  tree:add(tx_hdr_fields.sequence, tvbuf:range(offset, 8))
  advance(8)

  tb_count, offset = readInt(tvbuf, offset)
  if tb_count == 1 then
    tb_min, offset = readUInt64(tvbuf, offset)
    tb_max, offset = readUInt64(tvbuf, offset)

    tree:add(tx_hdr_fields.tb_min, tb_max)
    tree:add(tx_hdr_fields.tb_max, tb_min)
  end

  memo_type, offset = readInt(tvbuf, offset)
  if memo_type == 0 then
    -- no-op
  elseif memo_type == 1 then
    len, offset = readInt(tvbuf, offset)
    tree:add(tx_hdr_fields.memo_str, tvbuf:range(offset, len))

    advance(len)
  elseif memo_type == 2 then
    tree:add(tx_hdr_fields.memo_data, tvbuf:range(offset, 32))
    advance(32)
  else
    advance(32)
  end

  count, offset = readInt(tvbuf, offset)
  tree:add(tx_hdr_fields.op_count, count)

  for _ = 1, count do
    offset = dissectOp(tvbuf, offset, tree)
  end

  advance(4) -- reserved

  count, offset = readInt(tvbuf, offset)
  for _ = 1, count do
    advance(4) -- hint

    count, offset = readInt(tvbuf, offset)
    tree:add(tx_hdr_fields.signature, tvbuf:range(offset, count))
    advance(count)
  end

  return offset
end

dissectOp = function(tvbuf, offset, root)
  local advance = function(v) offset = offset + v end

  local tree = root:add(operation_proto, tvbuf:range(offset, tvbuf:len() - offset))

  addDest = function()
    tree:add(op_hdr_fields.destination, tvbuf:range(offset + 4, 32))
    tree:add(op_hdr_fields.destination_s, publicKey(tvbuf:raw(offset + 4, 32))):set_generated(true)
    offset = offset + 36
  end

  count, offset = readInt(tvbuf, offset)
  if count == 1 then
    tree:add(op_hdr_fields.source, tvbuf:range(offset + 4, 32))
    tree:add(op_hdr_fields.source_s, publicKey(tvbuf:raw(offset + 4, 32))):set_generated(true)
    offset = offset + 36
  end

  type, offset = readInt(tvbuf, offset)

  if type == 0 then
    tree:append_text(" - " .. "Create Account")

    addDest()

    tree:add(op_hdr_fields.amount, tvbuf:range(offset, 8))
    advance(8)
  elseif type == 1 then
    tree:append_text(" - " .. "Payment")

    addDest()

    local asset
    type, offset = readInt(tvbuf, offset)
    if type == 0 then
      asset = "native"
    elseif type == 1 then
      asset = tvbuf:range(offset, 4)
      offset = offset + 40
    else
      asset = tvbuf:range(offset, 12)
      offset = offset + 48
    end

    tree:add(op_hdr_fields.asset, asset)

    tree:add(op_hdr_fields.amount, tvbuf:range(offset, 8))
    advance(8)
  end

  return offset
end

message_types_funcs = {
  [message_types.ERROR_MSG]   = dissectError,
  [message_types.GET_TX_SET]  = dissectGetTxSet,
  [message_types.TX_SET]      = dissectTxSet,
  [message_types.TRANSACTION] = dissectTx,
  [message_types.SCP_MESSAGE] = dissectSCPMessage,
}

-- statement dissectors

dissectNominate = function(tvbuf, offset, root)
  local tree = root:add(nomination_proto, tvbuf:range(offset, tvbuf:len() - offset))

  tree:add(nom_hdr_fields.qs_hash, tvbuf:range(offset, 32))
  offset = offset + 32

  vote_count, offset = readInt(tvbuf, offset)

  for _ = 1, vote_count do
    vote_length, offset = readInt(tvbuf, offset)

    tree:add(nom_hdr_fields.votes, tvbuf:range(offset, vote_length))
    offset = offset + vote_length
  end

  accepted_count, offset = readInt(tvbuf, offset)

  for _ = 1, accepted_count do
    accepted_length, offset = readInt(tvbuf, offset)

    tree:add(nom_hdr_fields.accepted, tvbuf:range(offset, accepted_length))
    offset = offset + accepted_length
  end

  return offset
end

function dissectBallot(tvbuf, offset, root, label)
  local tree = root:add(ballot_proto, tvbuf:range(offset, tvbuf:len() - offset))

  counter, offset = readUInt32(tvbuf, offset)
  tree:add(blt_hdr_fields.counter, counter)

  value_length, offset = readInt(tvbuf, offset)

  tree:add(blt_hdr_fields.value, tvbuf:range(offset, value_length))
  offset = offset + value_length

  tree:set_text(label)

  return offset
end

dissectPrepare = function(tvbuf, offset, root)
  local tree = root:add(prepare_proto, tvbuf:range(offset, tvbuf:len() - offset))

  tree:add(prep_hdr_fields.qs_hash, tvbuf:range(offset, 32))
  offset = offset + 32

  offset = dissectBallot(tvbuf, offset, tree, "Ballot")

  count, offset = readInt(tvbuf, offset)
  if count == 1 then
    offset = dissectBallot(tvbuf, offset, tree, "Prepare")
  end

  count, offset = readInt(tvbuf, offset)
  if count == 1 then
    offset = dissectBallot(tvbuf, offset, tree, "Prepare'")
  end

  nc, offset = readUInt32(tvbuf, offset)
  tree:add(prep_hdr_fields.nC, nc)

  nh, offset = readUInt32(tvbuf, offset)
  tree:add(prep_hdr_fields.nH, nh)

  return offset
end

dissectConfirm = function(tvbuf, offset, root)
  local tree = root:add(confirm_proto, tvbuf:range(offset, tvbuf:len() - offset))

  offset = dissectBallot(tvbuf, offset, tree, "Ballot")

  nPrepared, offset = readUInt32(tvbuf, offset)
  tree:add(cfrm_hdr_fields.nPrepared, nPrepared)

  nCommit, offset = readUInt32(tvbuf, offset)
  tree:add(cfrm_hdr_fields.nCommit, nCommit)

  nh, offset = readUInt32(tvbuf, offset)
  tree:add(cfrm_hdr_fields.nH, nh)

  tree:add(cfrm_hdr_fields.qs_hash, tvbuf:range(offset, 32))
  offset = offset + 32

  return offset
end

dissectExternalize = function(tvbuf, offset, root)
  local tree = root:add(externalize_proto, tvbuf:range(offset, tvbuf:len() - offset))

  offset = dissectBallot(tvbuf, offset, tree, "Commit ballot")

  nh, offset = readUInt32(tvbuf, offset)
  tree:add(ext_hdr_fields.nH, nh)

  tree:add(ext_hdr_fields.qs_hash, tvbuf:range(offset, 32))
  offset = offset + 32

  return offset
end

statement_types_funcs = {
  [statement_types.SCP_ST_NOMINATE] = dissectNominate,
  [statement_types.SCP_ST_PREPARE] = dissectPrepare,
  [statement_types.SCP_ST_CONFIRM] = dissectConfirm,
  [statement_types.SCP_ST_EXTERNALIZE] = dissectExternalize,
}

checkScpLength = function (tvbuf, offset)
  -- "msglen" is the number of bytes remaining in the Tvb buffer which we
  -- have available to dissect in this run
  local msglen = tvbuf:len() - offset

  -- check if capture was only capturing partial packet size
  if msglen ~= tvbuf:reported_length_remaining(offset) then
      -- captured packets are being sliced/cut-off, so don't try to desegment/reassemble
      return 0
  end

  if msglen < 4 then
      -- we need more bytes, so tell the main dissector function that we
      -- didn't dissect anything, and we need an unknown number of more
      -- bytes (which is what "DESEGMENT_ONE_MORE_SEGMENT" is used for)
      -- return as a negative number
      return -DESEGMENT_ONE_MORE_SEGMENT
  end

  -- if we got here, then we know we have enough bytes in the Tvb buffer
  -- to at least figure out the full length of this SCP messsage (the length
  -- is the 32-bit integer in first 4 bytes)

  -- get the TvbRange of bytes 0-3
  local length_tvbr = tvbuf:range(offset, 4)

  -- get the length as an unsigned integer, in network-order (big endian)
  local length_val = length_tvbr:uint()

  -- XDR messages set the high bit to indicate EOF.  Clear it.
  length_val = length_val - 0x80000000

  if msglen < length_val + 4 then
      -- we need more bytes to get the whole SCP message
      return -(length_val - msglen)
  end

  return length_val, length_tvbr
end

DissectorTable.get("tcp.port"):add(11625, scp_proto)
