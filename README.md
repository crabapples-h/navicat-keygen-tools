# Navicat Keygen

[中文版README](README.zh-CN.md)

This repository will tell you how Navicat offline activation works.

[How does it work?](HOW_DOES_IT_WORK.md)

## 1. How to build

* Before you build keygen, you should make sure you have following libs:
 
  ```
  openssl
  capstone
  keystone
  rapidjson
  ```

  You can install them by 
  
  ```shell
  $ brew install openssl
  $ brew install capstone
  $ brew install keystone
  $ brew install rapidjson
  ```

* Clone `mac` branch and build keygen and patcher:

  ```shell
  $ git clone -b mac https://github.com/DoubleLabyrinth/navicat-keygen.git
  $ cd navicat-keygen
  $ make all
  ```

  You will see two executable files in `bin/` folder:

  ```shell
  $ ls bin/
  navicat-keygen    navicat-patcher
  ```

## 2. How to Use

1. Build keygen and patcher.

2. Backup your `Navicat Premium.app/Contents/MacOS/Navicat Premium` and all of your saved database connection configurations (with password). 

3. Remove all connections, if have, that Navicat saved in `Keychain.app`. 

   You can find them by search with keyword `navicat` in `Keychain.app`.

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

   ```shell
   $ ./navicat-patcher /Applications/Navicat\ Premium.app/Contents/MacOS/Navicat\ Premium
   ```

   It has been tested on __Navicat Premium 12.1.15 For Mac Simplified Chinese__ version. The following is an example of output:

   ```
   ***************************************************
   *       Navicat Patcher by @DoubleLabyrinth       *
   *                  Version: 3.0                   *
   ***************************************************

   Press Enter to continue or Ctrl + C to abort.

   PatchSolution0 ...... Ready to apply.
       Info: Keyword offset = +0x02d3c48c
   PatchSolution1 ...... Omitted.
   PatchSolution2 ...... Ready to apply.
       Info: Target function offset = +0x00f650a2
       Info: Keyword offset = +0x02ed1bc8
       Info: std::string::append(const char*) offset = +02613e44
   MESSAGE: Generating new RSA private key, it may take a long time.
   MESSAGE: New RSA private key has been saved to RegPrivateKey.pem.

   Your RSA public key:
   -----BEGIN PUBLIC KEY-----
   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt1haNfmdWMA2V11CqGIB
   +vce/v0mulh5SNcpto6yaklyup6UO4ryVea9L2X8Tw2rh1xwcqJjD29a8MNaMB7B
   6FbLAdLleNjcWBUSfWeomOIrWHtGIfUUyMLrFAhAx0Vj5EjTZVv3F7r1HaCUEyq9
   wT3rC1XQs4YKzE9dL+sGXB+BuCg2l0eQPFojc+k48IbuMIUPqR63g9IfXtjqS6vt
   6rbeWk3nB0QEzOVPVrrRP6sZAZzovY21ZQ/5cw6WE3x03SGtjbsS65KaHfUljHGH
   IjQF0OhH7teS3AYGv7ydRUTRJ/nvT9JnWM7MQfJ8uq1Hc6JLW7sKhBNf/Ia6Tkvz
   gwIDAQAB
   -----END PUBLIC KEY-----

   ****************************
   *   Begin PatchSolution0   *
   ****************************
   @+0x02d3c48c
   Previous:
   +0x0000000002d3c480  73 0a 25 73 0a 25 73 0a 25 73 0a 00 2d 2d 2d 2d  s.%s.%s.%s..----
   +0x0000000002d3c490  2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45  -BEGIN PUBLIC KE
   +0x0000000002d3c4a0  59 2d 2d 2d 2d 2d 00 4d 49 49 42 49 6a 41 4e 42  Y-----.MIIBIjANB
   +0x0000000002d3c4b0  67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41  gkqhkiG9w0BAQEFA
   ...
   ...
   ...
   After:
   +0x0000000002d3c480  73 0a 25 73 0a 25 73 0a 25 73 0a 00 2d 2d 2d 2d  s.%s.%s.%s..----
   +0x0000000002d3c490  2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45  -BEGIN PUBLIC KE
   +0x0000000002d3c4a0  59 2d 2d 2d 2d 2d 00 4d 49 49 42 49 6a 41 4e 42  Y-----.MIIBIjANB
   +0x0000000002d3c4b0  67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41  gkqhkiG9w0BAQEFA
   ...
   ...
   ...

   ****************************
   *   Begin PatchSolution2   *
   ****************************
   @+0x02ed1bc8
   Previous:
   +0x0000000002ed1bc0  ee 00 00 00 17 00 00 00 42 49 6a 57 79 6f 65 52  ........BIjWyoeR
   +0x0000000002ed1bd0  52 30 4e 42 67 6b 71 6e 44 5a 57 78 43 67 4b 43  R0NBgkqnDZWxCgKC
   +0x0000000002ed1be0  45 41 77 31 64 71 46 33 44 54 76 4f 42 39 31 5a  EAw1dqF3DTvOB91Z
   ...
   ...
   ...
   After:
   +0x0000000002ed1bc0  ee 00 00 00 17 00 00 00 4d 49 49 42 49 6a 41 4e  ........MIIBIjAN
   +0x0000000002ed1bd0  42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46  BgkqhkiG9w0BAQEF
   +0x0000000002ed1be0  41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43  AAOCAQ8AMIIBCgKC
   ...
   ...
   ...

   @+0x00f650a2
   Previous:
   +0x0000000000f650a0  0f 0b 55 48 89 e5 41 57 41 56 53 48 83 ec 48 c6  ..UH..AWAVSH..H.
   +0x0000000000f650b0  45 e5 01 31 c0 88 45 e6 48 89 fb 88 45 e7 0f 57  E..1..E.H...E..W
   +0x0000000000f650c0  c0 48 8d 7d a0 0f 29 07 48 c7 47 10 00 00 00 00  .H.}..).H.G.....
   +0x0000000000f650d0  48 8d 35 ef 74 e0 01 e8 68 ed 6a 01 e8 19 e8 00  H.5.t...h.j.....
   +0x0000000000f650e0  00 88 45 e5 e8 77 e8 00 00 88 45 e6 e8 d5 e8 00  ..E..w....E.....
   +0x0000000000f650f0  00 88 45 e7 f6 45 e7 01 0f 85 35 0c 00 00 f6 45  ..E..E....5....E
   After:
   +0x0000000000f650a0  0f 0b 55 48 89 e5 41 57 41 56 53 48 83 ec 48 48  ..UH..AWAVSH..HH
   +0x0000000000f650b0  89 fb 48 31 c0 48 89 04 24 48 89 44 24 08 48 89  ..H1.H..$H.D$.H.
   +0x0000000000f650c0  44 24 10 48 8d 3c 24 48 8d 35 fa ca f6 01 e8 71  D$.H.<$H.5.....q
   +0x0000000000f650d0  ed 6a 01 48 8b 04 24 48 89 03 48 8b 44 24 08 48  .j.H..$H..H.D$.H
   +0x0000000000f650e0  89 43 08 48 8b 44 24 10 48 89 43 10 48 89 d8 48  .C.H.D$.H.C.H..H
   +0x0000000000f650f0  83 c4 48 5b 41 5e 41 5f 5d c3 35 0c 00 00 f6 45  ..H[A^A_].5....E

   MESSAGE: PatchSolution0 has been applied.
   MESSAGE: PatchSolution2 has been applied.
   MESSAGE: Patch has been done successfully. Have fun and enjoy~
   ```

   __FOR Navicat Premium version < 12.0.24 ONLY:__

   `navicat-patcher` will abort and won't modify target file. 
   
   You should use openssl to generate `RegPrivateKey.pem` and `rpk` file.
   
   ```shell
   $ openssl genrsa -out RegPrivateKey.pem 2048
   $ openssl rsa -in RegPrivateKey.pem -pubout -out rpk
   ```
   
   Then replace 

   ```
   /Applications/Navicat Premium.app/Contents/Resources/rpk
   ```

   by `rpk` you just generated.

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

