#!/usr/bin/env bash
bin_dir=`cd "$(dirname "$BASH_SOURCE[0]")"; pwd`
[ -f "$bin_dir/requirements.txt" ] && python3 -m venv env && pip install -r requirements.txt && 
python3 $bin_dir/sync-aliases.py "$@"