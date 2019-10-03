#!/usr/bin/env bash

cd `dirname "$0"`
navicat_root=`pwd`

# Wine environment variables
WINEDIR="wine"
export LANG="en_US.UTF-8"
export PATH="$navicat_root/$WINEDIR/bin":"$navicat_root":"$navicat_root/$WINEDIR/drive_c/windows":"$PATH"
export LD_LIBRARY_PATH="$navicat_root/$WINEDIR/lib":"$navicat_root/lib":"$LD_LIBRARY_PATH"
export WINEDLLPATH="$navicat_root/$WINEDIR/lib/wine"
export WINELOADER="$navicat_root/$WINEDIR/bin/wine64"
export WINESERVER="$navicat_root/$WINEDIR/bin/wineserver"
export WINEPREFIX="$HOME/.navicat64"
export WINEDEBUG=-all   # suppress all wine debug info

exec "${WINELOADER:-wine}" "navicat-keygen.exe" "-text" "RegPrivateKey.pem"
