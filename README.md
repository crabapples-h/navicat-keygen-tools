# Navicat Keygen

[中文版README](README.zh-CN.md)

This repository will tell you how Navicat offline activation works.

[How does it work?](HOW_DOES_IT_WORK.md)

## 1. How to build

* Before you build keygen, you should make sure you have `OpenSSL` lib and `rapidjson` lib.
  
  If you have `brew`, you can install them by 
  
  ```bash
  $ brew install openssl
  $ brew install rapidjson
  ```

* Clone `mac` branch and build keygen and patcher:

  ```bash
  $ git clone -b mac https://github.com/DoubleLabyrinth/navicat-keygen.git
  $ cd navicat-keygen
  $ make all
  ```

  You will see two executable files in `bin/` folder:

  ```bash
  $ ls bin/
  navicat-keygen    navicat-patcher
  ```

## 2. How to Use

1. Build keygen and patcher.

2. Backup your `Navicat Premium.app/Contents/MacOS/Navicat Premium` and all of your saved database connection configurations (with password). 

3. Remove all connections, if have, that Navicat saved in `Keychain.app`. 

   You can find them by search with keyword `navicat`.

4. Use `navicat-patcher` to replace __Navicat Activation Public Key__.
   
   ```
   Usage:
       navicat-patcher <navicat executable file> [RSA-2048 PrivateKey(PEM file)]
   ```

   * `<navicat executable file>`: The path to Navicat executable file.
     
     __This parameter must be specified.__

   * `[RSA-2048 PrivateKey(PEM file)]`: The path to an RSA-2048 private key file. 
     
     __This parameter is optional.__ If not specified, `navicat-patcher` will generate a new RSA-2048 private key file `RegPrivateKey.pem` at current directory.

   __Example:__ 

   ```
   $ ./navicat-patcher /Applications/Navicat\ Premium.app/Contents/MacOS/Navicat\ Premium
   ```

   __FOR Navicat Premium version < 12.0.24 ONLY:__

   `navicat-patcher` will not modify target file. But you should use openssl to convert `RegPrivateKey.pem` to `rpk` file and replace 

   ```
   /Applications/Navicat Premium.app/Contents/Resources/rpk
   ```

   by it. 

   If you don't know how to use openssl, here's an example:

   ```bash
   $ openssl rsa -in RegPrivateKey.pem -pubout -out rpk
   ```

5. __Generate a self-signed code-sign certificate and always trust it.__

   __Then use `codesign` to re-sign `Navicat Premium.app`.__

   ```
   $ codesign -f -s "Your self-signed code-sign certificate name" <path to Navicat Premium.app>
   ```

   __NOTICE:__ 
   
   "Your self - signed code - sign certificate name" is the name of your certificate, not path.

   __Example:__

   ```bash
   $ codesign -f -s "foobar" /Applications/Navicat\ Premium.app/
   ```

6. Then use `navicat-keygen` to generate __snKey__ and __Activation Code__.

   ```
   Usage:
      navicat-keygen <RSA-2048 PrivateKey(PEM file)>
   ```

   * `<RSA-2048 PrivateKey(PEM file)>`: The path to a RSA-2048 private key file. 
     
     __This parameter must be specified.__

   __Example:__

   ```bash
   ./navicat-keygen ./RegPrivateKey.pem
   ```

   You will be asked to select Navicat language and input major version number. After that an randomly generated __snKey__ will be given.

   ```
   Which is your Navicat Premium language?
   0. English
   1. Simplified Chinese
   2. Traditional Chinese
   3. Japanese
   4. Polish
   5. Spanish
   6. French
   7. German
   8. Korean
   9. Russian
   10. Portuguese

   (Input index)> 1
   (Input major version number, range: 0 ~ 15, default: 12)> 12

   Serial number:
   NAVK-MWQR-LNXV-886V

   Your name: 
   ```

   You can use this __snKey__ to activate your Navicat preliminarily.
     
   Then you will be asked to input `Your name` and `Your organization`. Just set them whatever you want, but not too long.

   ```bash
   Your name: DoubleLabyrinth
   Your organization: DoubleLabyrinth
   Input request code (in Base64), input empty line to end:
   ```
     
   After that, you will be asked to input the request code. Now __DO NOT CLOSE KEYGEN__.

7. __Disconnect your network__ and open Navicat Premium. 

   Find and click `Registration`. Fill license key by __Serial number__ that the keygen gave and click `Activate`.

8. Generally online activation will fail and Navicat will ask you do `Manual Activation`, just choose it.

9. Copy your request code and paste it in the keygen. Input empty line to tell the keygen that your input ends.

   ```bash
   Your name: DoubleLabyrinth
   Your organization: DoubleLabyrinth

   Input request code (in Base64), input empty line to end:
   q/cv0bkTrG1YDkS+fajFdi85bwNVBD/lc5jBYJPOSS5bfl4DdtnfXo+RRxdMjJtEcYQnvLPi2LF0
   OB464brX9dqU29/O+A3qstSyhBq5//iezxfu2Maqca4y0rVtZgQSpEnZ0lBNlqKXv7CuTUYCS1pm
   tEPgwJysQTMUZf7tu5MR0cQ+hY/AlyQ9iKrQAMhHklqZslaisi8VsnoIqH56vfTyyUwUQXrFNc41
   qG5zZNsXu/NI79JOo7qTvcFHQT/k5cTadbKTxY+9c5eh+nF3JR7zEa2BDDfdQRLNvy4DTSyxdYXd
   sAk/YPU+JdWI+8ELaa0SuAuNzr5fEkD6NDSG2A==

   Request Info:
   {"K":"NAVADHCNP2OIDV46", "DI":"Y2eJk9vrvfGudPG7Mbdn", "P":"MAC"}

   Response Info:
   {"K":"NAVADHCNP2OIDV46","DI":"Y2eJk9vrvfGudPG7Mbdn","N":"DoubleLabyrinth","O":"DoubleLabyrinth","T":1537630251}

   License:
   oyoMYr9cfVGXeT7F1dqBwHsB/vvWj6SUL6aR+Kzb0lm5IyEj1CgovuSq+qMzFfx+
   oHMFaGKFg6viOY2hfJcrO2Vdq0hXZS/B/Ie3jBS2Ov37v8e3ufVajaH+wLkmEpLd
   xppCVLkDQjIHYR2IPz5s/L/RuWqDpEY4TPmGFF6q+xQMnqQA3vXPyG+JYMARXLru
   Y1gCDLN30v3DpyOeqKmFjUqiHK5h8s0NYiH2OpMyaCpi12JsF23miP89ldQp3+SJ
   8moo0cNGy7sFp2gX9ol2zVoo7qxfYlLl03f7CALJ6im0sx4yBsmlzFDdvpQUbXk8
   YZ5rT4LML2Fx6Wgnnklb5g==
   ```

10. Finally, you will get __Activation Code__ which looks like a Base64 string. Just copy it and paste it in Navicat `Manual Activation` window, then click `Activate`. If nothing wrong, activation should be done successfully.

