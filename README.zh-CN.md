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
  ```
  
  如果你有`brew`的话，你可以通过
  
  ```
  $ brew install openssl
  $ brew install capstone
  $ brew install keystone
  $ brew install rapidjson
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

2. 备份好 `Navicat Premium.app/Contents/MacOS/Navicat Premium` 以及Navicat中所有已保存的数据库连接（包括密码）。

3. 移除所有Navicat在 `Keychain.app` （即钥匙链）中保存的连接，如果有的话。

   你可以通过搜索关键词 `navicat` 来找到它们。

4. 使用`navicat-patcher`替换掉公钥：

   ```
   Usage:
       navicat-patcher <navicat executable file> [RSA-2048 PrivateKey(PEM file)]
   ```

   * `<navicat executable file>`: Navicat可执行文件的路径。
     
     __这个参数必须指定。__

   * `[RSA-2048 PrivateKey(PEM file)]`: RSA-2048私钥文件的路径。
     
     __这个参数是可选的。__ 如果没有指定，`navicat-patcher`将会在当前目录下生成一个新的RSA-2048私钥文件`RegPrivateKey.pem`。

   __例如：__

   ```
   $ ./navicat-patcher /Applications/Navicat\ Premium.app/Contents/MacOS/Navicat\ Premium
   ```

   __Navicat Premium For Mac 12.1.15 简体中文版__ 已通过测试。下面将是一份样例输出：

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

   __仅对 Navicat Premium 版本 < 12.0.24 的说明：__

   如果你的Navicat版本小于12.0.24，那么`navicat-patcher`将会终止并且不会修改目标文件。
   
   你必须使用openssl生成`RegPrivateKey.pem`和`rpk`文件：

   ```shell
   $ openssl genrsa -out RegPrivateKey.pem 2048
   $ openssl rsa -in RegPrivateKey.pem -pubout -out rpk
   ``` 

   接着用刚生成的`rpk`文件替换

   ```
   /Applications/Navicat Premium.app/Contents/Resources/rpk
   ```

5. __生成一份自签名的代码证书，并总是信任该证书。这一步非常重要。__

   __然后用`codesign`对`Navicat Premium.app`重签名。__

   ```bash
   $ codesign -f -s "Your self-signed code-sign certificate name" <path to Navicat Premium.app>
   ```

   __注意：__ 
   
   "Your self-signed code-sign certificate name"是你证书的名字，不是路径。

   __例如：__

   ```bash
   $ codesign -f -s "foobar" /Applications/Navicat\ Premium.app/
   ```

6. 接下来使用`navicat-keygen`来生成 __序列号__ 和 __激活码__。

   ```
   Usage:
       navicat-keygen <RSA-2048 PrivateKey(PEM file)>
   ```

   * `<RSA-2048 PrivateKey(PEM file)>`: RSA-2048私钥文件的路径。
     
     __这个参数必须指定。__

   __例如：__ 

   ```bash
   ./navicat-keygen ./RegPrivateKey.pem
   ```

   你会被要求选择Navicat的语言以及输入主版本号。之后会随机生成一个 __序列号__。

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

   你可以使用这个 __序列号__ 暂时激活Navicat。

   接下来你会被要求输入`用户名`和`组织名`；请随便填写，但不要太长。

   ```bash
   Your name: DoubleLabyrinth
   Your organization: DoubleLabyrinth
   Input request code (in Base64), input empty line to end:
   ```
 
   之后你会被要求填入请求码。注意 __不要关闭注册机__.

7. __断开网络__ 并打开Navicat。找到`注册`窗口，填入注册机给你的序列号。然后点击`激活`按钮。

8. 一般来说在线激活肯定会失败，这时候Navicat会询问你是否`手动激活`，直接选吧。

9. 在`手动激活`窗口你会得到一个请求码，复制它并把它粘贴到keygen里。最后别忘了连按至少两下回车结束输入。

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

10. 如果不出意外，你会得到一个看似用Base64编码的激活码。直接复制它，并把它粘贴到Navicat的`手动激活`窗口，最后点`激活`按钮。如果没什么意外的话应该能成功激活。
