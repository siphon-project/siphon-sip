from siphon import proxy

# Reply to every request with a large body. A handful of unread replies then
# fill the kernel send buffer (which autotunes to ~MBs) plus the per-connection
# channel, so a single non-reading peer backs up fast — the condition that, on a
# buggy build, parks the outbound distributor in send().await while it holds the
# connection-map shard guard (stalling ALL outbound + blocking accept()).
BIG = "A" * 262144  # 256 KiB


@proxy.on_request
def route(request):
    request.set_reply_body(BIG, "application/octet-stream")
    request.reply(200, "OK")
