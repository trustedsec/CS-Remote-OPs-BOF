#!/bin/bash

# variables
HOME=$(pwd)
BOF=$1
SRCDIR="$HOME/src/Injection/$BOF"
OUTDIR="$HOME/Injection/$BOF"
PKGS=$HOME/packages

# compile
echo "[+] Changing directory: $SRCDIR"
cd $SRCDIR
echo "[+] Compiling: $BOF"
make

# archive
echo "[+] Creating artifact:"
mkdir artifacts # $SRCDIR/artifacts/
mv $OUTDIR/*.o ./artifacts/
VERSION=$(git describe --tags --abbrev=0)
cat extension.json | jq ".version |= \"$VERSION\"" > ./artifacts/extension.json
cd artifacts # ./src/Injection/$BOF/artifacts/
echo
pwd
ls -l
echo

# package
mkdir -p $PKGS
echo "[+] Creating package:"
MANIFEST=$(cat extension.json | base64 -w 0)
COMMAND_NAME=$(cat extension.json | jq -r .command_name)
echo "[+] executing: tar -czvf $PKGS/$COMMAND_NAME.tar.gz ."
tar -czvf $PKGS/$COMMAND_NAME.tar.gz .
cd $PKGS
echo
pwd
ls -l

# sign
echo "[+] Signing package:"
bash -c "echo \"\" | /home/runner/minisign -s /home/runner/minisign.key -S -m ./$COMMAND_NAME.tar.gz -t \"$MANIFEST\" -x $COMMAND_NAME.minisig"