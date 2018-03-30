# Navicat Keygen

  This repository will tell you how Navicat offline activation works.

## 1. Keyword Explanation.

  * __Navicat Activation Public Key__

    It is a __RSA-2048__ public key that Navicat used to encrypt or decrypt offline activation information.

    It is stored in __navicat.exe__ as a kind of resource called __RCData__. The resource name is `"ActivationPubKey"`. You can see it by a kind of software [___Resource Hacker___](http://www.angusj.com/resourcehacker/). The concrete content is:

    > -----BEGIN PUBLIC KEY-----  
    > MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I  
    > qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv  
    > a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF  
    > R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2  
    > WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt  
    > YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ  
    > awIDAQAB  
    > -----END PUBLIC KEY-----  

    If you have the corresponding private key, please tell me. I would be very appreciated for your generous.

    __NOTICE:__

    Start from __Navicat Premium 12.0.25__, Navicat do not load this public key from resource in `navicat.exe`. Actually the public key is stored in `libcc.dll` and encrypted. And to avoid being replaced easily, the public key is split into 5 parts:

    The content below is discovered from `libcc.dll` of Navicat Premium x64 12.0.25 Simplified Chinese version. SHA256 value is `607e0a84c75966b00f3d12fa833e91d159e4f51ac51b6ba66f98d0c3cbefdce0`. I do not guaranteed that __offset__ value is absolutely correct in other versions. But __char string__ and __immediate values__ is highly possible to be found.

      1. At file offset `+ 0x1A12090` in `libcc.dll`, stored as __char string__:  

         > "D75125B70767B94145B47C1CB3C0755E  
         >  7CCB8825C5DCE0C58ACF944E08280140  
         >  9A02472FAFFD1CD77864BB821AE36766  
         >  FEEDE6A24F12662954168BFA314BD950  
         >  32B9D82445355ED7BC0B880887D650F5"  

      2. At file offset `+ 0x59D799` in `libcc.dll`, stored as __immediate value__ in a instruction:

         > 0xFE 0xEA 0xBC 0x01

         In decimal: `29158142`

      3. At file offset `+ 0x1A11DA0` in `libcc.dll`, stored as __char string__:

         > "E1CED09B9C2186BF71A70C0FE2F1E0AE  
         >  F3BD6B75277AAB20DFAF3D110F75912B  
         >  FB63AC50EC4C48689D1502715243A79F  
         >  39FF2DE2BF15CE438FF885745ED54573  
         >  850E8A9F40EE2FF505EB7476F95ADB78  
         >  3B28CA374FAC4632892AB82FB3BF4715  
         >  FCFE6E82D03731FC3762B6AAC3DF1C3B  
         >  C646FE9CD3C62663A97EE72DB932A301  
         >  312B4A7633100C8CC357262C39A2B3A6  
         >  4B224F5276D5EDBDF0804DC3AC4B8351  
         >  62BB1969EAEBADC43D2511D6E0239287  
         >  81B167A48273B953378D3D2080CC0677  
         >  7E8A2364F0234B81064C5C739A8DA28D  
         >  C5889072BF37685CBC94C2D31D0179AD  
         >  86D8E3AA8090D4F0B281BE37E0143746  
         >  E6049CCC06899401264FA471C016A96C  
         >  79815B55BBC26B43052609D9D175FBCD  
         >  E455392F10E51EC162F51CF732E6BB39  
         >  1F56BBFD8D957DF3D4C55B71CEFD54B1  
         >  9C16D458757373E698D7E693A8FC3981  
         >  5A8BF03BA05EA8C8778D38F9873D62B4  
         >  460F41ACF997C30E7C3AF025FA171B5F  
         >  5AD4D6B15E95C27F6B35AD61875E5505  
         >  449B4E"

      4. At file offset `+ 0x59D77F` in `libcc.dll`, stored as __immediate value__ in a instruction:

         > 0x59 0x08 0x01 0x00          (in decimal )

         In decimal: `67673`

      5. At file offset `+ 0x1A11D8C` in `libcc.dll`, stored as __char string__:

         > "92933"

    Then output encrypted public key with format `"%s%d%s%d%s"`, the order is the same as it list:

      > D75125B70767B94145B47C1CB3C0755E7CCB8825C5DCE0C58ACF944E082801409A02472FAFFD1CD77864BB821AE36766FEEDE6A24F12662954168BFA314BD95032B9D82445355ED7BC0B880887D650F529158142E1CED09B9C2186BF71A70C0FE2F1E0AEF3BD6B75277AAB20DFAF3D110F75912BFB63AC50EC4C48689D1502715243A79F39FF2DE2BF15CE438FF885745ED54573850E8A9F40EE2FF505EB7476F95ADB783B28CA374FAC4632892AB82FB3BF4715FCFE6E82D03731FC3762B6AAC3DF1C3BC646FE9CD3C62663A97EE72DB932A301312B4A7633100C8CC357262C39A2B3A64B224F5276D5EDBDF0804DC3AC4B835162BB1969EAEBADC43D2511D6E023928781B167A48273B953378D3D2080CC06777E8A2364F0234B81064C5C739A8DA28DC5889072BF37685CBC94C2D31D0179AD86D8E3AA8090D4F0B281BE37E0143746E6049CCC06899401264FA471C016A96C79815B55BBC26B43052609D9D175FBCDE455392F10E51EC162F51CF732E6BB391F56BBFD8D957DF3D4C55B71CEFD54B19C16D458757373E698D7E693A8FC39815A8BF03BA05EA8C8778D38F9873D62B4460F41ACF997C30E7C3AF025FA171B5F5AD4D6B15E95C27F6B35AD61875E5505449B4E6767392933

    This encrypted public key can be decrypted by my another repo: [how-does-navicat-encrypt-password](https://github.com/DoubleLabyrinth/how-does-navicat-encrypt-password), while the key used is `b'23970790'`

    Example:

    ```cmd
    E:\GitHub>git clone https://github.com/DoubleLabyrinth/how-does-navicat-encrypt-password.git
    ...
    E:\GitHub>cd how-does-navicat-encrypt-password\python3
    E:\GitHub\how-does-navicat-encrypt-password\python3>python
    Python 3.6.3 (v3.6.3:2c5fed8, Oct  3 2017, 18:11:49) [MSC v.1900 64 bit (AMD64)] on win32
    Type "help", "copyright", "credits" or "license" for more information.
    >>> from NavicatCrypto import *
    >>> cipher = Navicat11Crypto(b'23970790')
    >>> print(cipher.DecryptString('D75125B70767B94145B47C1CB3C0755E7CCB8825C5DCE0C58ACF944E082801409A02472FAFFD1CD77864BB821AE36766FEEDE6A24F12662954168BFA314BD95032B9D82445355ED7BC0B880887D650F529158142E1CED09B9C2186BF71A70C0FE2F1E0AEF3BD6B75277AAB20DFAF3D110F75912BFB63AC50EC4C48689D1502715243A79F39FF2DE2BF15CE438FF885745ED54573850E8A9F40EE2FF505EB7476F95ADB783B28CA374FAC4632892AB82FB3BF4715FCFE6E82D03731FC3762B6AAC3DF1C3BC646FE9CD3C62663A97EE72DB932A301312B4A7633100C8CC357262C39A2B3A64B224F5276D5EDBDF0804DC3AC4B835162BB1969EAEBADC43D2511D6E023928781B167A48273B953378D3D2080CC06777E8A2364F0234B81064C5C739A8DA28DC5889072BF37685CBC94C2D31D0179AD86D8E3AA8090D4F0B281BE37E0143746E6049CCC06899401264FA471C016A96C79815B55BBC26B43052609D9D175FBCDE455392F10E51EC162F51CF732E6BB391F56BBFD8D957DF3D4C55B71CEFD54B19C16D458757373E698D7E693A8FC39815A8BF03BA05EA8C8778D38F9873D62B4460F41ACF997C30E7C3AF025FA171B5F5AD4D6B15E95C27F6B35AD61875E5505449B4E6767392933'))
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I
    qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv
    a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF
    R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2
    WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt
    YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ
    awIDAQAB
    -----END PUBLIC KEY-----
    ```

  * __Request Code__

    It is a Base64 string that represents 256-bytes-long data, while the 256-bytes-long data is the cipher text of the __offline activation information__ encrypted by __Navicat Activation Public Key__.

  * __Offline Activation Request Information__

    It is just a JSON-style ASCII string which contains 3 items. Respectively they are `"K"`, `"DI"` and `"P"`, which represent __snKey__, __DeviceIdentifier__ (related with your machine), __Platform__ (Appropriately speaking, it should be OS Type).

    Like:  
    > {"K": "xxxxxxxxxxxxxxxx", "DI": "yyyyyyyyyyyyy", "P": "WIN8"}

  * __Activation Code__

    It is a Base64 string that represents 256-bytes-long data, while the 256-bytes-long data is the cipher text of the __offline activation response information__ encrypted by __Navicat Activation Private Key__ (so far, we don't know official activation private key).

  * __Offline Activation Response Information__

    Just like __Offline Activation Request Information__, it is also a JSON-style ASCII string. But it contains 5 items. Respectively they are `"K"`, `"N"`, `"O"`, `"T"`, '`DI`'.

    `"K"` and `"DI"` has the same meaning mentioned in __Offline Activation Request Information__ and must be same with the corresponding items in __Offline Activation Request Information__.

    `"N"`, `"O"`, `"T"` represent __Name__, __Organization__, __Time__ respectively. __Name__ and __Organization__ are string and the type of __Time__ can be string or integer (Thanks for discoveries from @Wizr, issue #10).

    `"T"` can be omitted.

  * __snKey__

    It is a 4-block-long string, while every block is 4-chars-long.

    __snKey__ is generated by 10-bytes-long data. In order to explain it easily, I use __data[10]__ to represent the 10-bytes-long data.

    1. __data[0]__ and __data[1]__ must be `0x68` and `0x2A` respectively.

       _`May change when Navicat product changes. Uncertain yet.`_  

    2. __data[2]__, __data[3]__ and __data[4]__ can be any byte. Just set them whatever you want.

       _`May change when Navicat product changes. Uncertain yet. But it's very possible right.`_  

    3. __data[5]__ and __data[6]__ are related with your Navicat product language. It depends.

       ~~_`May change when Navicat product changes. Uncertain yet.`_~~  
       _`Must change when Navicat product changes. Confirmed yet.`_

       |  Language  |  data[5]  |  data[6]  |  Discoverer     |
       |------------|-----------|-----------|-----------------|
       |  English   |  0xAC     |  0x88     |                 |
       |  简体中文   |  0xCE     |  0x32     |                 |
       |  繁體中文   |  0xAA     |  0x99     |                 |
       |  日本語     |  0xAD     |  0x82     |  @dragonflylee  |
       |  Polski    |  0xBB     |  0x55     |  @dragonflylee  |
       |  Español   |  0xAE     |  0x10     |  @dragonflylee  |
       |  Français  |  0xFA     |  0x20     |  @Deltafox79    |
       |  Deutsch   |  0xB1     |  0x60     |  @dragonflylee  |
       |  한국어     |  0xB5     |  0x60     |  @dragonflylee  |
       |  Русский   |  0xEE     |  0x16     |  @dragonflylee  |
       |  Português |  0xCD     |  0x49     |  @dragonflylee  |

       According to __Navicat 12 for Mac x64__ version, what IDA 7.0 indicates is that this two bytes are product signature.

    4. __data[7]__ represents whether it is __commercial license__ or __non-commercial license__.

       For __Navicat 12 x64__: `0x65` is __commercial license__, `0x66` is __non-commercial license__.  
       For __Navicat 11 x64__: `0x15` is __commercial license__, `0x16` is __non-commercial license__.  

       _`May change when Navicat product changes. Uncertain yet.`_  
       _`Must change when version change.`_  

       According to __Navicat 12 for Mac x64__ version, what IDA 7.0 indicates is that commercial license is __Enterprise License__ and non-commercial license is __Educational License__.

    5. High 4 bits of __data[8]__ represents __version number__. Low 4 bits is unknown, but we can use it to delay activation deadline. Possible value is `0000` or `0001`.

       For __Navicat 12 x64__: High 4 bits must be `1100`, which is the binary of number `12`.  
       For __Navicat 11 x64__: High 4 bits must be `1011`, which is the binary of number `11`.  

       _`Must change when version change. Confirmed by Navicat 12 for Mac x64 with IDA Pro 7.0`_  

    6. __data[9]__ is unknown, but you can set it `0xFD` or `0xFC` or `0xFB` if you want to use __not-for-resale license__.

       _`May change when Navicat product changes. Uncertain yet.`_  

       According to __Navicat 12 for Mac x64__ version, what IDA 7.0 indicates is that:

       * `0xFB` is __Not-For-Resale-30-days__ license.  
       * `0xFC` is __Not-For-Resale-90-days__ license.  
       * `0xFD` is __Not-For-Resale-365-days__ license.  
       * `0xFE` is __Not-For-Resale__ license.  
       * `0xFF` is __Site__ license.  

    -----------------

    After that. Navicat use __DES__ with __ECB mode__ to encrypt the last 8 bytes which are from __data[2]__ to __data[9]__.

    The DES key is:

    ```cpp
    unsigned char DESKey = { 0x64, 0xAD, 0xF3, 0x2F, 0xAE, 0xF2, 0x1A, 0x27 };
    ```

    Then encode the 10-bytes-long data: __(Use Base32 encode if you just want a conclusion.)__

    1. Regard __data[10]__ as a 80-bits-long data.

       If __data[10]__ starts with `0x68` and `0x2A`, so the 80-bits-long data is `01011000 00101010......`

    2. Divide the 80-bits-long data as 16 5-bits-long blocks.

       If __data[10]__ starts with `0x68` and `0x2A`, so the 80-bits-long data is `01011`, `00000`, `10101`, `0....`, ...

    3. So the value every block is less than 32. Map them by a encode-table:

       ```cpp
       char EncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
       ```

       Then you will get a 16-char-long string.

       If __data[10]__ starts with `0x68` and `0x2A`, so after encoded, it should starts with `"N"`, `"A"`, `"V"`.

    4. Divide the 16-char-long string to four 4-chars-long blocks, Then you get __snKey__.

## 3. Activation Process

  1. Check whether __sn_Key__ that user inputs is legal.

  2. After user clicks `Activate`, Navicat will start online activation first. If fails, user can choose offline activation.

  3. Navicat will use the __snKey__ that user inputs and some information collected from user's machine to generate __Offline Activation Request Information__, then encrypt it by __Navicat Activation Public Key__ and return Base64-encoded string as __Request Code__.

  4. In legal way, the __Request Code__ should be sent to Navicat official activation server by a Internet-accessible computer. And Navicat official activation server will return a legal __Activation Code__.

     But now, we use keygen to play the official activation server's role.

     1. According to the __Request Code__, Get `"DI"` value and `"K"` value.

     2. Fill __Offline Activation Response Information__ with `"K"` value, name, organization name and `"DI"` value.

     3. Encrypt __Offline Activation Response Information__ by __Navicat Activation Private Key__ and you will get 256-byte-long data.

     4. Encode 256-byte-long data by Base64. The result is __Activation Code__.

  5. Input __Activation Code__, then offline activation is done.

## 4. How to use
  1. Build patcher and keygen in Release configuration or download the latest release.

  2. Replace __Navicat Activation Public Key__ in `navicat.exe` or `libcc.dll`.  
     Example:  

     * For Navicat Premium version < 12.0.25
       ```bash
       E:\GitHub\navicat-keygen\x64\Release>navicat-patcher.exe "D:\Program Files\PremiumSoft\Navicat Premium 12"
       D:\Program Files\PremiumSoft\Navicat Premium 12\navicat.exe has been backed up.
       Public key has been replaced.
       Success!
       ```

     * For Navicat Premium version >= 12.0.25
       ```bash
       E:\GitHub\navicat-keygen\x64\Release>navicat-patcher.exe "D:\Program Files\PremiumSoft\Navicat Premium 12"
       D:\Program Files\PremiumSoft\Navicat Premium 12\libcc.dll has been backed up.
       Public key has been replaced.
       Success!
       ```
       You may wait for a few seconds or even longer, because patcher is search for a appropriate RSA key. Finally you will get `RegPrivateKey.pem` file at current directory.

       If you do not want to search, use `RegPrivateKey.pem` in my latest release, then:
       ```bash
       E:\GitHub\navicat-keygen\x64\Release>navicat-patcher.exe "D:\Program Files\PremiumSoft\Navicat Premium 12" RegPrivateKey.pem
       D:\Program Files\PremiumSoft\Navicat Premium 12\libcc.dll has been backed up.
       Public key has been replaced.
       Success!
       ```

  3. Then in console:

     ```bash
     E:\GitHub\navicat-keygen\x64\Release>navicat-keygen.exe RegPrivateKey.pem

     ```

     You will get a __snKey__ and be asked to input your name and organization.  
     Just input and then you will be asked to input the request code. Now __DO NOT CLOSE KEYGEN__.

  4. Disconnect network and open Navicat Premium, find and click `Registration`. Then input `Registration Key` by snKey that keygen gave. Then click `Activate`.

  5. Generally online activation will failed and Navicat will ask you do `Manual Activation`, just choose it.

  6. Copy your request code and paste it in keygen. Input empty line to tell keygen that your input ends.

  7. Then you will get activation code which looks like a Base64 string. Just copy it and paste it in Navicat `Manual Activation` window, then click Activate. If nothing is wrong, activation should be done successfully.
