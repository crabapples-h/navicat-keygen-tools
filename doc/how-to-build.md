# Navicat Keygen - How to build?

[中文版](how-to-build.zh-CN.md)

## 1. Prerequisites

1. Please make sure that you have __Visual Studio 2019__ or the higher. Because this is a VS2019 project.

2. Please make sure you have installed `vcpkg` and the following libraries:

   * `capstone[x86]:x64-windows-static`
   * `capstone[x86]:x86-windows-static`
   * `openssl-windows:x64-windows-static`
   * `openssl-windows:x86-windows-static`
   * `rapidjson:x64-windows-static`
   * `rapidjson:x86-windows-static`

   is installed.

   You can install them by:

   ```console
   $ vcpkg install capstone[x86]:x64-windows-static
   $ vcpkg install capstone[x86]:x86-windows-static
   $ vcpkg install openssl-windows:x64-windows-static
   $ vcpkg install openssl-windows:x86-windows-static
   $ vcpkg install rapidjson:x64-windows-static
   $ vcpkg install rapidjson:x86-windows-static
   ```

3. Your `vcpkg` has been integrated into your __Visual Studio__, which means you have run 

   ```console
   $ vcpkg integrate install
   ```

   successfully.

## 2. Build

1. Open this project in __Visual Studio__.

2. Select `Release` configuration. 

3. Select `Win32` to build keygen/patcher for 32-bits Navicat.

   Or select `x64` to build keygen/patcher for 64-bits Navicat.

4. Select __Build > Build Solution__.

You will see executable files in `bin/` directory. 

