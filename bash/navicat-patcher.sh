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

# 将斜线替换为反斜线
navicat_root_back_slash=${navicat_root//\//\\}
# 前缀
prefix='Z:\'
# 后缀
suffix='\Navicat'
# wine环境中的navicat路径
navicat_path="$prefix$navicat_root_back_slash$suffix"

# wine执行navicat-patcher.exe
exec "${WINELOADER:-wine}" "navicat-patcher.exe" "$navicat_path"