# Navicat Keygen - How to build?

[中文版](how-to-build.zh-CN.md)

## 1. Prerequisites

1. Please make sure you have installed following libraries:

   * `capstone`
   * `keystone`
   * `rapidjson`

   If you use Ubuntu, you can install them by:

   ```console
   # install capstone
   $ sudo apt-get install libcapstone-dev

   # install keystone
   $ sudo apt-get install cmake
   $ git clone https://github.com/keystone-engine/keystone.git
   $ cd keystone
   $ mkdir build
   $ cd build
   $ ../make-share.sh
   $ sudo make install
   $ sudo ldconfig

   # install rapidjson
   $ sudo apt-get install rapidjson-dev

   or if you use Fedora, you can install them by:

   ```console
   # install capstone
   $ sudo dnf install capstone-devel

   # install keystone
   $ sudo dnf install cmake
   $ sudo dnf install gcc
   $ sudo dnf install g++
   $ git clone https://github.com/keystone-engine/keystone.git
   $ cd keystone
   $ mkdir build
   $ cd build
   $ ../make-share.sh # if error update "cmake_minimum_required(VERSION 2.8.7...3.22)" that match your cmake version in CMakeLists.txt file
   $ sudo make install
   $ sudo echo /usr/local/lib64 >> /etc/ld.so.conf
   $ sudo ldconfig

   # install rapidjson
   $ sudo dnf install rapidjson-devel
   ```

2. Your gcc supports C++17 feature.

## 2. Build

```console
$ make all
```

You will see executable files in `bin/` directory. 
