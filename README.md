# Navicat Keygen

[中文版README](README.zh-CN.md)

This repository will tell you how Navicat offline activation works.

[How does it work?](HOW_DOES_IT_WORK.md)

## How to use?

1. Download the latest release [from here](https://github.com/DoubleLabyrinth/navicat-keygen/releases).

2. Use `navicat-patcher.exe` to replace __Navicat Activation Public Key__ that is stored in `navicat.exe` and `libcc.dll`.
   
   ```
   navicat-patcher.exe <Navicat installation path> [RSA-2048 PEM file]
   ```

   * `<Navicat installation path>`: The full path to Navicat installation folder. 
     
     __This parameter must be specified.__

   * `[RSA-2048 PEM file]`: The full path or relative path to a RSA-2048 private key file. 
     
     __This parameter is optional.__ If not specified, `navicat-patcher.exe` will generate a new RSA-2048 private key file `RegPrivateKey.pem` at current directory.

   __Example: (in cmd.exe)__ 

   ```
   navicat-patcher.exe "C:\Program Files\PremiumSoft\Navicat Premium 12" .\RegPrivateKey.pem
   ```
   
   It has been tested on __Navicat Premium 12.1.7 Simplified Chinese version__. The following is an example of output.

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

3. Then use `navicat-keygen.exe` to generate __snKey__ and __Activation Code__

   ```
   navicat-keygen.exe <-bin|-text> [-adv] <RSA-2048 PrivateKey(PEM file)>
   ```

   * `<-bin|-text>`: Must be `-bin` or `-text`. 
  
     If `-bin` is specified, `navicat-keygen.exe` will finally generate `license_file`. It is used for Navicat old activation method only.

     If `-text` is specified, `navicat-keygen.exe` will finally generate a Base64-style string which is __Activation Code__. It is used for Navicat new activation method. 

     __This parameter must be specified.__

   * `[-adv]`: Enable advanced mode.

     __This parameter is optional.__ If specified, `navicat-keygen.exe` will ask you input Navicat product ID number, language signature numbers. It is for future use generally.

   * `<RSA-2048 PrivateKey(PEM file)>`: The full path or relative path to a RSA-2048 private key file. 
     
     __This parameter must be specified.__

   __Example: (in cmd.exe)__

   ```bash
   navicat-keygen.exe -text .\RegPrivateKey.pem
   ```

   You will be asked to select Navicat product, language and input major version number. After that an randomly generated __snKey__ will be given.

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

   You can use this __snKey__ to activate your Navicat preliminarily.
     
   Then you will be asked to input `Your name` and `Your organization`. Just set them whatever you want, but not too long.

   ```bash
   Your name: DoubleLabyrinth
   Your organization: DoubleLabyrinth
   Input request code (in Base64), input empty line to end:
   ```
     
   After that, you will be asked to input the request code. Now __DO NOT CLOSE KEYGEN__.

4. __Disconnect your network__ and open Navicat. Find and click `Registration`. Fill `Registration Key` by __snKey__ that the keygen gave and click `Activate`.

5. Generally online activation will failed and Navicat will ask you do `Manual Activation`, just choose it.

6. Copy your request code and paste it in the keygen. Input empty line to tell the keygen that your input ends.

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

7. Finally, you will get __Activation Code__ which looks like a Base64 string. Just copy it and paste it in Navicat `Manual Activation` window, then click `Activate`. If nothing wrong, activation should be done successfully.

