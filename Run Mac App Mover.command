#!/bin/zsh
DIR="$(dirname "$0")"
if [ -f "$DIR/server.py" ]; then
    cd "$DIR"
else
    cd "/Volumes/Razer/code/mac_app_mover"
fi
python3 server.py
