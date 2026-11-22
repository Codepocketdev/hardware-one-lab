#!/bin/bash
set -e
BASE=9d4f7db2b06fc91e2b5d64d6d6426fb0cd44a3d7
P=~/hardware-one-lab/patches
R=~/trezor-firmware/legacy/firmware
G="git -c user.name=lab -c user.email=lab@lab.invalid"
cd ~/trezor-firmware
git worktree remove --force /tmp/pgen 2>/dev/null || true
git worktree remove --force /tmp/pcheck 2>/dev/null || true
git worktree add /tmp/pgen $BASE >/dev/null 2>&1
cd /tmp/pgen
git apply $P/01-clock.patch
git apply $P/02-nostr-signer.patch
git add -A && $G commit -qm "01+02"
cp $R/layout2.c.pre-cashu1 legacy/firmware/layout2.c
cp $R/trezor.c legacy/firmware/trezor.c
echo "== 03 mode toggle =="; git diff --stat
git diff > $P/03-mode-toggle.patch
git add -A && $G commit -qm "03"
cp $R/layout2.c legacy/firmware/layout2.c
cp $R/fsm_msg_common.h legacy/firmware/fsm_msg_common.h
echo "== 04 cashu =="; git diff --stat
git diff > $P/04-cashu.patch
cd ~/trezor-firmware
git worktree remove --force /tmp/pgen
git worktree add /tmp/pcheck $BASE >/dev/null 2>&1
cd /tmp/pcheck
for p in 01-clock 02-nostr-signer 03-mode-toggle 04-cashu; do
  git apply $P/$p.patch && echo "$p applies"
done
for f in layout2.c fsm_msg_common.h trezor.c; do
  diff -q legacy/firmware/$f $R/$f && echo "same as flashed tree: $f"
done
cd ~/trezor-firmware && git worktree remove --force /tmp/pcheck
