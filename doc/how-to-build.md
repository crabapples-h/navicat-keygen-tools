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
   ```

2. Your gcc supports C++17 feature.

## 2. Build

```console
$ git clone -b linux --single-branch https://github.com/DoubleLabyrinth/navicat-keygen.git
$ cd navicat-keygen
$ make all
```

You will see executable files in `bin/` directory. 
