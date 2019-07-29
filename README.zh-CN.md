# Navicat Keygen

这份repo将会告诉你Navicat是怎么完成离线激活的。

[注册机是怎么工作的?](HOW_DOES_IT_WORK.zh-CN.md)

## 1. 如何编译

* 在编译之前，你应该确保你有如下几个库：

  ```
  openssl
  capstone
  keystone
  rapidjson
  libplist
  ```
  
  如果你有`brew`的话，你可以通过
  
  ```
  $ brew install openssl
  $ brew install capstone
  $ brew install keystone
  $ brew install rapidjson
  $ brew install libplist
  ```
  
  来完成它们的安装。

* Clone `mac` 分支，并编译keygen和patcher

  ```bash
  $ git clone -b mac https://github.com/DoubleLabyrinth/navicat-keygen.git
  $ cd navicat-keygen
  $ make all
  ```

  编译完成后你会在 `bin/` 文件夹下看到两个可执行文件： 

  ```bash
  $ ls bin/
  navicat-keygen    navicat-patcher
  ```

## 2. 如何使用这个Keygen

1. 编译好keygen和patcher。

2. 备份好Navicat中所有已保存的数据库连接（包括密码）。

3. 移除所有Navicat在 `Keychain Access.app` （即钥匙链）中保存的连接，如果有的话。

   你可以通过在 `Keychain Access.app` 中搜索关键词 `navicat` 来找到它们。

4. 使用`navicat-patcher`替换掉公钥：

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

   * `<Navicat installation path>`: `Navicat Premium.app` 的路径。
     
     __这个参数必须指定。__

   * `[RSA-2048 PrivateKey(PEM file)]`: PEM格式的RSA-2048私钥文件路径。
     
     __这个参数是可选的。__ 
     
     如果没有指定，`navicat-patcher`将会在当前目录下生成一个新的RSA-2048私钥文件`RegPrivateKey.pem`。

   __例如：__

   ```console
   $ ./navicat-patcher /Applications/Navicat\ Premium.app/
   ```

   __Navicat Premium For Mac 12.1.24 简体中文版__ 已通过测试。下面将是一份样例输出：

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

   * __仅对 Navicat Premium 版本 < 12.0.24 的说明：__

     如果你的Navicat版本小于12.0.24，那么`navicat-patcher`将会终止并且不会修改目标文件。
   
     你必须使用openssl生成`RegPrivateKey.pem`和`rpk`文件：

     ```console
     $ openssl genrsa -out RegPrivateKey.pem 2048
     $ openssl rsa -in RegPrivateKey.pem -pubout -out rpk
     ``` 

     接着用刚生成的`rpk`文件替换

     ```
     /Applications/Navicat Premium.app/Contents/Resources/rpk
     ```

5. __生成一份自签名的代码证书，并总是信任该证书。这一步非常重要。__

   __然后用`codesign`对`Navicat Premium.app`重签名。__

   ```console
   $ codesign -f -s "Your self-signed code-sign certificate name" <path to Navicat Premium.app>
   ```

   __注意：__ 
   
   "Your self-signed code-sign certificate name"是你证书的名字，不是路径。

   __例如：__

   ```console
   $ codesign -f -s "foobar" /Applications/Navicat\ Premium.app/
   ```

6. 接下来使用`navicat-keygen`来生成 __序列号__ 和 __激活码__。

   ```
   Usage:
       navicat-keygen <RSA-2048 Private Key File>

           <RSA-2048 Private Key File>    Path to a PEM-format RSA-2048 private key file.
                                          This parameter must be specified.
   ```

   * `<RSA-2048 Private Key File>`: PEM格式的RSA-2048私钥文件路径。
     
     __这个参数必须指定。__

   __例如：__ 

   ```console
   $ ./navicat-keygen ./RegPrivateKey.pem
   ```

   你会被要求选择Navicat的语言以及输入主版本号。之后会随机生成一个 __序列号__。

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

   你可以使用这个 __序列号__ 暂时激活Navicat。

   接下来你会被要求输入`用户名`和`组织名`；请随便填写，但不要太长。

   ```console
   Your name: DoubleLabyrinth
   Your organization: DoubleLabyrinth
   Input request code (in Base64), input empty line to end:
   ```
 
   之后你会被要求填入请求码。注意 __不要关闭注册机__。

7. __断开网络__ 并打开Navicat。

   找到`注册`窗口，填入注册机给你的序列号。然后点击`激活`按钮。

8. 一般来说在线激活肯定会失败，这时候Navicat会询问你是否`手动激活`，直接选吧。

9. 在`手动激活`窗口你会得到一个请求码，复制它并把它粘贴到keygen里。最后别忘了连按至少两下回车结束输入。

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

10. 如果不出意外，你会得到一个看似用Base64编码的激活码。

    直接复制它，并把它粘贴到Navicat的`手动激活`窗口，最后点`激活`按钮。
    
    如果没什么意外的话应该能成功激活。
