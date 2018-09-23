# Navicat Keygen

这份repo将会告诉你Navicat是怎么完成离线激活的。

[注册机是怎么工作的?](HOW_DOES_IT_WORK.zh-CN.md)

## 如何使用这个注册机

1. [从这里](https://github.com/DoubleLabyrinth/navicat-keygen/releases)下载最新的release。

2. 使用`navicat-patcher.exe`替换掉`navicat.exe`和`libcc.dll`里的Navicat激活公钥。 

   ```
   navicat-patcher.exe <Navicat installation path> [RSA-2048 PEM file]
   ```

   * `<Navicat installation path>`: Navicat的完整安装路径。 
     
     __这个参数必须指定。__

   * `[RSA-2048 PEM file]`: RSA-2048私钥文件的完整路径或相对路径。
     
     __这个参数是可选的。__ 如果未指定，`navicat-patcher.exe`将会在当前目录生成一个新的RSA-2048私钥文件。

   __例如：(在cmd.exe中)__ 

   ```
   navicat-patcher.exe "C:\Program Files\PremiumSoft\Navicat Premium 12" .\RegPrivateKey.pem
   ```
   
   __Navicat Premium 12.1.7 简体中文版已通过测试__。下面将是一份样例输出。

   ```
   MESSAGE: Navicat.exe has been found.
   MESSAGE: libcc.dll has been found.

   MESSAGE: [Solution0] Keyword has been found: offset = +0x0297a6e0.
   MESSAGE: [Solution1] Keywords[0] has been found: offset = +0x02057530.
   MESSAGE: [Solution1] Keywords[1] has been found: offset = +0x006c4f89.
   MESSAGE: [Solution1] Keywords[2] has been found: offset = +0x02057240.
   MESSAGE: [Solution1] Keywords[3] has been found: offset = +0x006c4f6f.
   MESSAGE: [Solution1] Keywords[4] has been found: offset = +0x0205722c.

   Your RSA public key:
   -----BEGIN PUBLIC KEY-----
   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtOZGsX7UoDPuxCfEuw4i
   yWDASpwaN19GaPNrTlWz6K7MKXGrAQpYD5gNZ8nGdfRgp52TErTHSNoRjgfpxGqK
   ApPUISsIanGMcyf/H2b8pGuz1oF19kVKSyZTPaVLbE+1Cw7FULbI04bc64XnWSHo
   aQAXrYKGpC7oDomRGMtx28figu3AHAk1UQrcCvE3+0ITTA7X8xaRwz6+gb+uLgCd
   iXyRYDodG8i+kk1YIt3f2mt7jH+uEHqBYjIfvvo6g5MZz4KNz7Ewc6+sDyO8bmlX
   eFnHo6YAgCcaHVvVtGNCxCd1O5wWHvUN985HHQYnFr7qzJaL9cPb735pP2hb0IXe
   ywIDAQAB
   -----END PUBLIC KEY-----


   MESSAGE: Navicat.exe has been backed up successfully.
   MESSAGE: libcc.dll has been backed up successfully.

   ......
   ......
   ......

   Solution0 has been done successfully.
   Solution1 has been done successfully.
   ```

3. 接下来使用`navicat-keygen.exe`来生成序列号和激活码

   ```
   navicat-keygen.exe <-bin|-text> [-adv] <RSA-2048 PrivateKey(PEM file)>
   ```

   * `<-bin|-text>`: 必须是`-bin`或`-text`。

     如果指定了`-bin`，`navicat-keygen.exe`最终将生成`license_file`文件。这个选项是给Navicat旧激活方式使用的。

     如果指定了`-text`，`navicat-keygen.exe`最终将生成Base64样式的激活码。这个选项是给Navicat新激活方式使用的。

     __这个参数必须指定。__

   * `[-adv]`: 开启高级模式。

     __这个参数是可选的。__ 如果指定了这个参数，`navicat-keygen.exe`将会要求你手工填写产品ID号、语言标识号。这个选项一般是给以后用的。

   * `<RSA-2048 PrivateKey(PEM file)>`: RSA-2048私钥文件的完整路径或相对路径。
     
     __这个参数必须指定。__

   __例如：(在cmd.exe中)__ 

   ```bash
   navicat-keygen.exe -text .\RegPrivateKey.pem
   ```

   你会被要求选择Navicat产品类别、语言以及输入主版本号。之后会随机生成一个序列号。

   ```
   Select Navicat product:
   1. DataModeler
   2. Premium
   3. MySQL
   4. PostgreSQL
   5. Oracle
   6. SQLServer
   7. SQLite
   8. MariaDB
   9. MongoDB
   10. ReportViewer

   (Input index)> 1

   Select product language:
   1. English
   2. Simplified Chinese
   3. Traditional Chinese
   4. Japanese
   5. Polish
   6. Spanish
   7. French
   8. German
   9. Korean
   10. Russian
   11. Portuguese

   (Input index)> 1

   (Input major version number, range: 0 ~ 15, default: 12)> 12

   Serial number:
   NAVA-DHCN-P2OI-DV46

   Your name: 
   ```

   你可以使用这个序列号暂时激活Navicat。

   接下来你会被要求输入`用户名`和`组织名`；请随便填写，但不要太长。

   ```bash
   Your name: DoubleLabyrinth
   Your organization: DoubleLabyrinth
   Input request code (in Base64), input empty line to end:
   ```
 
   之后你会被要求填入请求码。注意 __不要关闭命令行__.

4. __断开网络__ 并打开Navicat。找到`注册`窗口，并填入keygen给你的序列号。然后点击`激活`按钮。

5. 一般来说在线激活肯定会失败，这时候Navicat会询问你是否`手动激活`，直接选吧。

6. 在`手动激活`窗口你会得到一个请求码，复制它并把它粘贴到keygen里。最后别忘了连按至少两下回车结束输入。

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
   {"K":"NAVADHCNP2OIDV46", "DI":"Y2eJk9vrvfGudPG7Mbdn", "P":"WIN 8"}

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

  4. 如果不出意外，你会得到一个看似用Base64编码的激活码。直接复制它，并把它粘贴到Navicat的`手动激活`窗口，最后点`激活`按钮。如果没什么意外的话应该能成功激活。

