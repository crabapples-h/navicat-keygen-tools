# Navicat Keygen

[中文版README](README.zh-CN.md)

This repository will tell you how Navicat offline activation works.

[How does it work?](HOW_DOES_IT_WORK.md)

__NOTICE: This keygen only supports Navicat Premium.__

## 1. How to build

* Before you build keygen, you should make sure you have following libs:
 
  ```
  openssl
  capstone
  keystone
  rapidjson
  libplist
  ```

  You can install them by 
  
  ```shell
  $ brew install openssl
  $ brew install capstone
  $ brew install keystone
  $ brew install rapidjson
  $ brew install libplist
  ```

* Clone `mac` branch and build keygen and patcher:

  ```shell
  $ git clone -b mac https://github.com/DoubleLabyrinth/navicat-keygen.git
  $ cd navicat-keygen
  $ make all
  ```

  You will see two executable files in `bin/` directory:

  ```shell
  $ ls bin/
  navicat-keygen    navicat-patcher
  ```

## 2. How to Use

1. Build keygen and patcher.

2. Backup all of your saved database connection configurations (with password). 

3. Remove all connections, if have, that Navicat saved in `Keychain Access.app`. 

   You can find them by search with keyword `navicat` in `Keychain Access.app`.

4. Use `navicat-patcher` to replace __Navicat Activation Public Key__.
   
   ```
   Usage:
       navicat-patcher <Navicat installation path> [RSA-2048 Private Key File]

           <Navicat installation path>    Path to `Navicat Premium.app`.
                                          Example:
                                              /Applications/Navicat\ Premium.app/
                                          This parameter must be specified.

           [RSA-2048 Private Key File]    Path to a PEM-format RSA-2048 private key file.
                                          This parameter is optional.
   ```

   * `<Navicat installation path>`: The path to `Navicat Premium.app`.
     
     __This parameter must be specified.__

   * `[RSA-2048 PrivateKey(PEM file)]`: The path to an RSA-2048 private key file. 
     
     __This parameter is optional.__ 
     
     If not specified, `navicat-patcher` will generate a new RSA-2048 private key file `RegPrivateKey.pem` at current directory.

   __Example:__ 

   ```console
   $ ./navicat-patcher /Applications/Navicat\ Premium.app/
   ```

   It has been tested on __Navicat Premium 12.1.24 For Mac Simplified Chinese__ version. 
   
   The following is an example of output:

   ```console
   $ ./navicat-patcher /Applications/Navicat\ Premium.app/
   ***************************************************
   *       Navicat Patcher by @DoubleLabyrinth       *
   *                  Version: 4.0                   *
   ***************************************************

   Press Enter to continue or Ctrl + C to abort.

   [*] Your Navicat version: 12.1.24

   [+] PatchSolution0 ...... Ready to apply.
       Keyword offset = +0x024a7db8
   [-] PatchSolution1 ...... Omitted.
   [+] PatchSolution2 ...... Ready to apply.
       Function offset = +0x00ec9868
       Keyword offset = +0x0263fd60
       std::string::append(const char*) RVA = 0x000000010214b726

   [*] Generating new RSA private key, it may take a long time...
   [+] New RSA private key has been saved to RegPrivateKey.pem.

   [*] Your RSA public key:
   -----BEGIN PUBLIC KEY-----
   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA030QIDXRx372bGrne9kp
   uuAqpxaxJX0x6LVaOf8+Uan2SQnFH8frnuMDRg5PjdBnFWEJGqZmRD1fNkLOhhCE
   iFZWxrDgJcuEBrv5VlduQ4hlYIulcf6qilBZUaaX9Kb3R7+H8ClMb00HwLc/Iht5
   bd9krhU3CT3g2ZG00GxVhEF4a/zZMDjeuQvTUeeubIeriT/2YC+w/tKfGbqWvjC6
   wkbjXGbVICSiKzhzztS4BHbtQMl8v6doMhFVd/PEDNFQrbkEr3kbk/oD8AccL8iz
   aV17UHt4VW2fR8tMyTvcuhTaUtWmt/tL6Z1RzCqH+KvTv8GpH8qFcty89YXja7dL
   kQIDAQAB
   -----END PUBLIC KEY-----

   **************************************************************
   *                      PatchSolution0                        *
   **************************************************************
   @+0x024a7db8
   Previous:
   -0x0000000000000008                          2d 2d 2d 2d 2d 42 45 47          -----BEG
   +0x0000000000000008  49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d  IN PUBLIC KEY---
   +0x0000000000000018  2d 2d 00 4d 49 49 42 49 6a 41 4e 42 67 6b 71 68  --.MIIBIjANBgkqh
   +0x0000000000000028  6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41  kiG9w0BAQEFAAOCA
   ...
   ...
   ...
   After:
   -0x0000000000000008                          2d 2d 2d 2d 2d 42 45 47          -----BEG
   +0x0000000000000008  49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d  IN PUBLIC KEY---
   +0x0000000000000018  2d 2d 00 4d 49 49 42 49 6a 41 4e 42 67 6b 71 68  --.MIIBIjANBgkqh
   +0x0000000000000028  6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41  kiG9w0BAQEFAAOCA
   ...
   ...
   ...

   **************************************************************
   *                      PatchSolution2                        *
   **************************************************************
   @+0x0263fd60
   Previous:
   +0x0000000000000000  42 49 6a 57 79 6f 65 52 52 30 4e 42 67 6b 71 6e  BIjWyoeRR0NBgkqn
   +0x0000000000000010  44 5a 57 78 43 67 4b 43 45 41 77 31 64 71 46 33  DZWxCgKCEAw1dqF3
   +0x0000000000000020  44 54 76 4f 42 39 31 5a 48 77 65 63 4a 59 46 72  DTvOB91ZHwecJYFr
   +0x0000000000000030  64 4d 31 4b 45 68 31 79 56 65 52 6f 47 71 53 64  dM1KEh1yVeRoGqSd
   +0x0000000000000040  4c 4c 47 5a 47 55 6c 6e 67 69 67 33 4f 44 35 6d  LLGZGUlngig3OD5m
   ...
   ...
   ...

   @+0x00ec9868
   Previous:
   -0x0000000000000008                          55 48 89 e5 41 57 41 56          UH..AWAV
   +0x0000000000000008  53 48 83 ec 38 49 89 fe c6 45 e5 01 31 c0 88 45  SH..8I...E..1..E
   +0x0000000000000018  e6 88 45 e7 48 8d 35 c5 70 61 01 48 8d 5d b0 48  ..E.H.5.pa.H.].H
   +0x0000000000000028  89 df e8 49 d9 ff ff 48 8d 35 ef ed 60 01 48 89  ...I...H.5..`.H.
   +0x0000000000000038  df e8 80 1e 28 01 e8 3f f4 00 00 88 45 e5 e8 b7  ....(..?....E...
   +0x0000000000000048  f4 00 00 88 45 e6 e8 2f f5 00 00 88 45 e7 f6 45  ....E../....E..E
   After:
   -0x0000000000000008                          55 48 89 e5 41 57 41 56          UH..AWAV
   +0x0000000000000008  53 48 83 ec 48 48 89 fb 48 31 c0 48 89 04 24 48  SH..HH..H1.H..$H
   +0x0000000000000018  89 44 24 08 48 89 44 24 10 48 8d 3c 24 48 8d 35  .D$.H.D$.H.<$H.5
   +0x0000000000000028  cc 64 77 01 e8 8d 1e 28 01 48 8b 04 24 48 89 03  .dw....(.H..$H..
   +0x0000000000000038  48 8b 44 24 08 48 89 43 08 48 8b 44 24 10 48 89  H.D$.H.C.H.D$.H.
   +0x0000000000000048  43 10 48 89 d8 48 83 c4 48 5b 41 5e 41 5f 5d c3  C.H..H..H[A^A_].

   [+] PatchSolution0 has been applied.
   [+] PatchSolution2 has been applied.

   **************************************************************
   *   Patch has been done successfully. Have fun and enjoy~~   *
   *    DO NOT FORGET TO SIGN NAVICAT BY YOUR CERTIFICATE!!!    *
   **************************************************************
   ```

   * __FOR Navicat Premium version < 12.0.24 ONLY:__

     `navicat-patcher` will abort and won't apply any patch. 
   
     You should use openssl to generate `RegPrivateKey.pem` and `rpk` file.
   
     ```console
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

   ```console
   $ codesign -f -s "Your self-signed code-sign certificate name" <path to Navicat Premium.app>
   ```

   __NOTICE:__ 
   
   "Your self-signed code-sign certificate name" is the name of your certificate in `Keychain Access.app`, not path.

   __Example:__

   ```console
   $ codesign -f -s "foobar" /Applications/Navicat\ Premium.app/
   ```

6. Then use `navicat-keygen` to generate __snKey__ and __Activation Code__.

   ```
   Usage:
       navicat-keygen <RSA-2048 Private Key File>

           <RSA-2048 Private Key File>    Path to a PEM-format RSA-2048 private key file.
                                          This parameter must be specified.
   ```

   * `<RSA-2048 Private Key File>`: Path to a PEM-format RSA-2048 private key file. 
     
     __This parameter must be specified.__

   __Example:__

   ```console
   $ ./navicat-keygen ./RegPrivateKey.pem
   ```

   You will be asked to select Navicat language and give major version number. After that an randomly generated __snKey__ will be given.

   ```console
   $ ./navicat-keygen ./RegPrivateKey.pem
   ***************************************************
   *       Navicat Keygen by @DoubleLabyrinth        *
   *                  Version: 4.0                   *
   ***************************************************

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
   NAVG-Z5H9-NK2L-MAZJ

   Your name:
   ```

   You can use this __snKey__ to activate your Navicat preliminarily.
     
   Then you will be asked to input `Your name` and `Your organization`. Just set them whatever you want, but not too long.

   ```console
   Your name: DoubleLabyrinth
   Your organization: DoubleLabyrinth
   Input request code (in Base64), input empty line to end:
   ```
     
   After that, you will be asked to input request code. Now __DO NOT CLOSE KEYGEN__.

7. __Disconnect your network__ and open Navicat Premium. 

   Find and click `Registration`. 
   
   Fill license key by __Serial number__ that the keygen gave and click `Activate`.

8. Generally online activation will fail and Navicat will ask you do `Manual Activation`, just choose it.

9. Copy your request code and paste it in the keygen. Input empty line to tell the keygen that your input ends.

   ```console
   Your name: DoubleLabyrinth
   Your organization: DoubleLabyrinth

   Input request code (in Base64), input empty line to end:
   Nuk6pouXNhuGnqb2rBbxpDOiCFxhdJF4/gteYA/UZFUwqmhhphn3PAErvlxCtbUCf9Lzw02gfIFog3gmTB1C5JzPdeE5uuD6SAvhlQ7ZVOmdA66dvt6mDDpuf78cGio1Rpkd0D/6dLzgHnFJJPOfPtlIT5ZOLDiWkiSJm8d83+ckMBoMtcvpXCiwDIGb1KfVZwsgLojyrrO5OzakIzd2xQ8r3mEmbVbMl/zD0S5fO4agxEOp2WvpmM1cqom9Egll7kgcQG8A0z1Abqo1PrVBjjOsb/v8wy5V/469G6/uDT4AkZQSz8m/TX9ZQlZE3QBlzrJ+sTEkpMVhw3h3u6l4JQ==

   Request Info:
   {"K":"NAVGZ5H9NK2LMAZJ", "DI":"NGVlZjdjOTViMzYyMWI0", "P":"MAC"}

   Response Info:
   {"K":"NAVGZ5H9NK2LMAZJ","DI":"NGVlZjdjOTViMzYyMWI0","N":"DoubleLabyrinth","O":"DoubleLabyrinth","T":1564415636}

   License:
   Vd4QUzEw6DPNpJLYVKV6ZNDny0gsZWCXbKyrf2nF27iTM35YUBouXEcAB/Vy355V2z++7iXe/coKmV4kNZbywlBchI5ts7gOHnhXWzBYQ3yKsBYKob/7sxaiw7CXCmhM4mPLMzrp5okewCWjBjb51keZ4SA3F6j8HGIVYiZW3CAZtkjxs9uUoXvVIJr+Gt83TgU+sqiC4oSplokopAql2zWPieA9KuhPoCKiGLMvuQwv0wWWPc2HorY0AHAetsyZ8MN4utZ2ylQ9z/ZojwX1KViyh3xxnjWF7xXJljIdBA4tCi4QDqDLvTuICfUV7VeKzOUY+ZKCO0xGxkTe1HVwog==
   ```

10. Finally, you will get __Activation Code__ which looks like a Base64 string. 

    Just copy it and paste it in Navicat `Manual Activation` window, then click `Activate`. 
    
    If nothing wrong, activation should be done successfully.

