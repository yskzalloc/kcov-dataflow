#!/bin/bash
# Setup and search public-inbox for rust-for-linux
# Usage:
#   ./mail-search.sh init           # first-time: clone + index
#   ./mail-search.sh start          # start local NNTP daemon
#   ./mail-search.sh fetch          # fetch latest messages
#   ./mail-search.sh search "term"  # search subjects
#   ./mail-search.sh read <artnum>  # read an article

INBOX=/home/debian-sid/mail/rust-for-linux/rust-for-linux
NNTP_PORT=8080

case "$1" in
init)
    echo "Initializing rust-for-linux public-inbox mirror..."
    mkdir -p /home/debian-sid/mail/rust-for-linux
    git clone --mirror https://lore.kernel.org/rust-for-linux/0 \
        /home/debian-sid/mail/rust-for-linux/rust-for-linux/git/0.git
    public-inbox-init -V2 --ng org.kernel.vger.rust-for-linux \
        rust-for-linux "$INBOX" https://lore.kernel.org/rust-for-linux \
        rust-for-linux@vger.kernel.org
    public-inbox-index "$INBOX"
    echo "Done. Run '$0 fetch' to update, '$0 start' to launch NNTP."
    ;;

start)
    pkill -f "public-inbox-nntpd.*$NNTP_PORT" 2>/dev/null
    sleep 1
    public-inbox-nntpd -l nntp://127.0.0.1:$NNTP_PORT --daemonize
    echo "NNTP daemon running at nntp://127.0.0.1:$NNTP_PORT"
    ;;

fetch)
    echo "Fetching from lore.kernel.org..."
    public-inbox-fetch -C "$INBOX"
    # Sync local branch to fetched data
    git --git-dir="$INBOX/git/0.git" branch -f master remotes/origin/master 2>/dev/null
    echo "Indexing..."
    public-inbox-index "$INBOX"
    # Restart NNTP daemon
    pkill -f "public-inbox-nntpd.*$NNTP_PORT" 2>/dev/null
    sleep 1
    nohup public-inbox-nntpd -l nntp://127.0.0.1:$NNTP_PORT </dev/null >/dev/null 2>&1 &
    sleep 1
    echo "Done. NNTP at 127.0.0.1:$NNTP_PORT"
    ;;

search)
    shift
    QUERY="$*"
    python3 -c "
import socket, sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(30)
s.connect(('127.0.0.1', $NNTP_PORT))
s.recv(1024)
s.send(b'GROUP org.kernel.vger.rust-for-linux\r\n')
resp = s.recv(1024).decode()
parts = resp.split()
last = int(parts[3])
start = max(1, last - 5000)

s.send(f'XOVER {start}-{last}\r\n'.encode())
data = b''
while True:
    chunk = s.recv(65536)
    if not chunk: break
    data += chunk
    if b'\r\n.\r\n' in data: break

query = '$QUERY'.lower().split()
for line in data.decode(errors='replace').split('\n'):
    low = line.lower()
    if all(q in low for q in query):
        fields = line.split('\t')
        if len(fields) > 3:
            print(f'{fields[0]:>6} | {fields[3][:24]} | {fields[1][:80]}')

s.send(b'QUIT\r\n')
s.close()
"
    ;;

read)
    ARTNUM="$2"
    python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(('127.0.0.1', $NNTP_PORT))
s.recv(1024)
s.send(b'GROUP org.kernel.vger.rust-for-linux\r\n')
s.recv(1024)
s.send(b'ARTICLE $ARTNUM\r\n')
data = b''
while True:
    chunk = s.recv(65536)
    if not chunk: break
    data += chunk
    if b'\r\n.\r\n' in data: break
print(data.decode(errors='replace')[:5000])
s.send(b'QUIT\r\n')
s.close()
"
    ;;

*)
    echo "Usage: $0 {init|start|fetch|search \"query\"|read <artnum>}"
    echo ""
    echo "Commands:"
    echo "  init                        # clone and initialize local mirror"
    echo "  start                       # start NNTP daemon"
    echo "  fetch                       # update from lore.kernel.org"
    echo "  search \"query\"              # search subjects (AND match)"
    echo "  read <artnum>               # read article by number"
    echo ""
    echo "First-time setup:"
    echo "  $0 init && $0 start"
    echo ""
    echo "Source: https://lore.kernel.org/rust-for-linux"
    echo "NNTP:   nntp://nntp.lore.kernel.org/org.kernel.vger.rust-for-linux"
    ;;
esac
