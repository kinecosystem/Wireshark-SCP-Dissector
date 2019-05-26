hdr_fields =
{
    -- AuthenticatedMessage
    sequence = ProtoField.uint64("scp.sequence", "Sequence", base.DEC),

    -- StellarMessage
    tx_set_hash = ProtoField.bytes("scp.tx_set_hash", "Tx Set Hash", base.NONE),
    prev_hash   = ProtoField.bytes("scp.prev_hash", "Previous Ledger Hash", base.NONE),
    hmac        = ProtoField.bytes("scp.hmac", "HMAC SHA256", base.NONE),

    msg = ProtoField.bytes("scp.msg", "Message", base.NONE),
}

env_hdr_fields = {
  signature = ProtoField.bytes("scp.envelope.signature", "Signature", base.NONE),
}

stmt_hdr_fields = {
  node_id   = ProtoField.string("scp.statement.node_id", "NodeId", base.ASCII),
  slot_idx  = ProtoField.uint64("scp.statement.slot_idx", "Slot Index", base.DEC),
}

nom_hdr_fields = {
  qs_hash  = ProtoField.bytes("scp.nomination.qs_hash", "Quorum Set Hash", base.NONE),
  votes    = ProtoField.bytes("scp.nomination.votes", "Votes", base.NONE),
  accepted = ProtoField.bytes("scp.nomination.accepted", "Accepted", base.NONE),
}

prep_hdr_fields = {
  qs_hash = ProtoField.bytes("scp.prepare.qs_hash", "Quorum Set Hash", base.NONE),
  nC      = ProtoField.uint32("scp.prepare.nc", "nC", base.DEC),
  nH      = ProtoField.uint32("scp.prepare.nh", "nH", base.DEC),
}

cfrm_hdr_fields = {
  nPrepared = ProtoField.uint32("scp.confirm.nprepared", "nPrepared", base.DEC),
  nCommit   = ProtoField.uint32("scp.confirm.ncommit", "nCommit", base.DEC),
  nH        = ProtoField.uint32("scp.confirm.nh", "nH", base.DEC),
  qs_hash   = ProtoField.bytes("scp.confirm.qs_hash", "Quorum Set Hash", base.NONE),
}

blt_hdr_fields = {
  counter = ProtoField.uint32("scp.ballot.counter", "Counter", base.DEC),
  value   = ProtoField.bytes("scp.ballot.value", "Value", base.NONE),
}

ext_hdr_fields = {
  nH      = ProtoField.uint32("scp.externalize.nh", "nH", base.DEC),
  qs_hash = ProtoField.bytes("scp.externalize.qs_hash", "Quorum Set Hash", base.NONE),
}

tx_hdr_fields = {
  source    = ProtoField.string("scp.tx.source", "Source", base.ASCII),
  fee       = ProtoField.uint32("scp.tx.fee", "Fee", base.DEC),
  sequence  = ProtoField.uint64("scp.tx.sequence", "Sequence", base.DEC),
  tb_min    = ProtoField.uint64("scp.tx.tb.min", "Timebounds - Min", base.DEC),
  tb_max    = ProtoField.uint64("scp.tx.tb.max", "Timebounds - Max", base.DEC),
  memo_str  = ProtoField.string("scp.tx.memo.string", "Memo", base.ASCII),
  memo_data = ProtoField.bytes("scp.tx.memo.data", "Memo", base.NONE),
  op_count  = ProtoField.int32("scp.tx.op_count", "Op Count", base.DEC),
  signature = ProtoField.bytes("scp.tx.signature", "Signature", base.NONE),
}

op_hdr_fields = {
  source = ProtoField.string("scp.op.source", "Source", base.ASCII),

  -- payment
  destination = ProtoField.string("scp.op.destination", "Destination", base.ASCII),
  asset       = ProtoField.string("scp.op.asset", "Asset", base.ASCII),
  amount      = ProtoField.int64("scp.op.amount", "Amount", base.DEC),
}
