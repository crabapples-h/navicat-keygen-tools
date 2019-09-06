# Navicat Keygen - 如何编译？

## 1. 前提条件

1. 请确保你有 __Visual Studio 2019__ 或者更高版本。因为这是一个VS2019项目。

2. 请确保你安装了 `vcpkg` 以及下面几个库：

   * `capstone[x86]:x64-windows-static`
   * `capstone[x86]:x86-windows-static`
   * `openssl-windows:x64-windows-static`
   * `openssl-windows:x86-windows-static`
   * `rapidjson:x64-windows-static`
   * `rapidjson:x86-windows-static`

   你可以通过下面的命令来安装它们：

   ```console
   $ vcpkg install capstone[x86]:x64-windows-static
   $ vcpkg install capstone[x86]:x86-windows-static
   $ vcpkg install openssl-windows:x64-windows-static
   $ vcpkg install openssl-windows:x86-windows-static
   $ vcpkg install rapidjson:x64-windows-static
   $ vcpkg install rapidjson:x86-windows-static
   ```

3. 你的 `vcpkg` 已经和你的 __Visual Studio__ 集成了，即你曾成功运行了：

   ```console
   $ vcpkg integrate install
   ```

## 2. 编译

1. 在 __Visual Studio__ 打开这个项目。

2. 选择 `Release` 配置。

3. 选择 `Win32` 来生成供32位Navicat使用的keygen/patcher。

   或者选择 `x64` 来生成供64位Navicat使用的keygen/patcher。

4. 选择 __生成 > 生成解决方案__。

生成完成后，你会在 `bin/` 文件夹下看到编译后的keygen/patcher。

