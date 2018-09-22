# Navicat keygen - 注册机是怎么工作的？

## 1. 关键词解释.

* __Navicat激活公钥__

  这是一个2048位的RSA公钥，Navicat使用这个公钥来完成相关激活信息的加密和解密。

  这个公钥被作为 __RCData__ 类型的资源储存在 __navicat.exe__ 当中。资源名为`"ACTIVATIONPUBKEY"`。你可以使用一个叫[Resource Hacker](http://www.angusj.com/resourcehacker/)的软件来查看它。这个公钥的具体内容为：

  ```
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

  如果您有相应的私钥并乐意公开的话欢迎联系我，我将非常感谢您的慷慨。

  __注意：__

  从 __Navicat Premium 12.0.25__ 开始，Navicat不再从`navicat.exe`的资源中加载私钥。事实上，公钥转为从`libcc.dll`中加载，并且已经被加密。与此同时，为了防止被轻松地替换，加密的公钥被分到5个地方储存：

  以下内容是从 __Navicat Premium x64 12.0.25 简体中文版__ 的`libcc.dll`中发现的，`libcc.dll`的SHA256值为`607e0a84c75966b00f3d12fa833e91d159e4f51ac51b6ba66f98d0c3cbefdce0`。我不保证在Navicat的其他版本中相关偏移量和下述的相同，但相关的 __字符串__ 以及 __立即数__ 是很可能找得到的。

  1. 在`libcc.dll`中，文件偏移量`+0x01A12090`的地方，储存了加密公钥的第一部分，以 __字符串__ 的形式储存：  

     ```
     "D75125B70767B94145B47C1CB3C0755E  
      7CCB8825C5DCE0C58ACF944E08280140  
      9A02472FAFFD1CD77864BB821AE36766  
      FEEDE6A24F12662954168BFA314BD950  
      32B9D82445355ED7BC0B880887D650F5" 
     ```

  2. 在`libcc.dll`中，文件偏移量`+0x0059D799`的地方，储存了加密公钥的第二部分，以 __立即数__ 的形式储存在一条指令中：

     ```
     0xFE 0xEA 0xBC 0x01
     ```

     相应的十进制值为: `29158142`

  3. 在`libcc.dll`中，文件偏移量`+0x01A11DA0`的地方，储存了加密公钥的第三部分，以 __字符串__ 的形式储存：

     ```
     "E1CED09B9C2186BF71A70C0FE2F1E0AE  
      F3BD6B75277AAB20DFAF3D110F75912B  
      FB63AC50EC4C48689D1502715243A79F  
      39FF2DE2BF15CE438FF885745ED54573  
      850E8A9F40EE2FF505EB7476F95ADB78  
      3B28CA374FAC4632892AB82FB3BF4715  
      FCFE6E82D03731FC3762B6AAC3DF1C3B  
      C646FE9CD3C62663A97EE72DB932A301  
      312B4A7633100C8CC357262C39A2B3A6  
      4B224F5276D5EDBDF0804DC3AC4B8351  
      62BB1969EAEBADC43D2511D6E0239287  
      81B167A48273B953378D3D2080CC0677  
      7E8A2364F0234B81064C5C739A8DA28D  
      C5889072BF37685CBC94C2D31D0179AD  
      86D8E3AA8090D4F0B281BE37E0143746  
      E6049CCC06899401264FA471C016A96C  
      79815B55BBC26B43052609D9D175FBCD  
      E455392F10E51EC162F51CF732E6BB39  
      1F56BBFD8D957DF3D4C55B71CEFD54B1  
      9C16D458757373E698D7E693A8FC3981  
      5A8BF03BA05EA8C8778D38F9873D62B4  
      460F41ACF997C30E7C3AF025FA171B5F  
      5AD4D6B15E95C27F6B35AD61875E5505  
      449B4E"
     ```

  4. 在`libcc.dll`中，文件偏移量`+0x0059D77F`的地方，储存了加密公钥的第四部分，以 __立即数__ 的形式储存在一条指令中：

      ```
      0x59 0x08 0x01 0x00
      ```

     相应的十进制值为: `67673`

  5. 在`libcc.dll`中，文件偏移量`+0x01A11D8C`的地方，储存了加密公钥的第五部分，以 __字符串__ 的形式储存：

      ```
      "92933"
      ```

  这五部分按照`"%s%d%s%d%s"`的形式输出则为加密的公钥，顺序和上述的顺序相同，具体的输出为：

  ```

  D75125B70767B94145B47C1CB3C0755E7CCB8825C5DCE0C58ACF944E082801409A02472FAFFD1CD77864BB821AE36766FEEDE6A24F12662954168BFA314BD95032B9D82445355ED7BC0B880887D650F529158142E1CED09B9C2186BF71A70C0FE2F1E0AEF3BD6B75277AAB20DFAF3D110F75912BFB63AC50EC4C48689D1502715243A79F39FF2DE2BF15CE438FF885745ED54573850E8A9F40EE2FF505EB7476F95ADB783B28CA374FAC4632892AB82FB3BF4715FCFE6E82D03731FC3762B6AAC3DF1C3BC646FE9CD3C62663A97EE72DB932A301312B4A7633100C8CC357262C39A2B3A64B224F5276D5EDBDF0804DC3AC4B835162BB1969EAEBADC43D2511D6E023928781B167A48273B953378D3D2080CC06777E8A2364F0234B81064C5C739A8DA28DC5889072BF37685CBC94C2D31D0179AD86D8E3AA8090D4F0B281BE37E0143746E6049CCC06899401264FA471C016A96C79815B55BBC26B43052609D9D175FBCDE455392F10E51EC162F51CF732E6BB391F56BBFD8D957DF3D4C55B71CEFD54B19C16D458757373E698D7E693A8FC39815A8BF03BA05EA8C8778D38F9873D62B4460F41ACF997C30E7C3AF025FA171B5F5AD4D6B15E95C27F6B35AD61875E5505449B4E6767392933

  ```

  这个加密的公钥可以用我的另外一个repo（[how-does-navicat-encrypt-password](https://github.com/DoubleLabyrinth/how-does-navicat-encrypt-password)）解密，其中密钥为`b'23970790'`。

  例如：

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

* __请求码__

  这是一个Base64编码的字符串，代表的是长度为256字节的数据。这256字节的数据是 __离线激活信息__ 用 __Navicat激活公钥__ 加密的密文。

* __离线激活请求信息__

  这是一个JSON风格的字符串。它包含了3个Key：`"K"`、`"DI"`和`"P"`，分别代表 __序列号__、__设备识别码__（与你的电脑硬件信息相关）和 __平台__ (其实就是操作系统类型)。

  例如：  

  ```  
  {"K": "xxxxxxxxxxxxxxxx", "DI": "yyyyyyyyyyyyy", "P": "WIN8"}
  ```

* __激活码__

  这是一个Base64编码的字符串，代表的是长度为256字节的数据。这256字节的数据是 __离线激活回复信息__ 用 __Navicat激活私钥__ 加密的密文。目前我们不知道官方的 __Navicat激活私钥__，所以我们得替换掉软件里的公钥。

* __离线激活回复信息__

  和 __离线激活请求信息__ 一样，它也是一个JSON风格的字符串。但是它包含5个Key，分别为`"K"`、`"N"`、`"O"`、`"T"` 和 `"DI"`.

  `"K"` 和 `"DI"` 的意义与 __离线激活请求信息__ 中的相同，且Value必须与 __离线激活请求信息__ 中的相同。

  `"N"`、`"O"`、`"T"` 分别代表 __注册名__、__组织__、__授权时间__。
  
  __注册名__ 和 __组织__ 的值类型为UTF-8编码的字符串。__授权时间__ 的值类型可以为字符串或整数（感谢@Wizr在issue #10中的报告）。

    `"T"` 可以被省略。

* __序列号__

  这是一个被分为了4个部分的字符串，其中每个部分都是4个字符长。

  __序列号__ 是通过10个字节的数据来生成的。为了表达方便，我用 __uint8_t data[10]__ 来表示这10个字节。

  1. __data[0]__ 和 __data[1]__ 必须分别为 `0x68` 和 `0x2A`。

     这两个字节为Navicat的标志数。

  2. __data[2]__、__data[3]__ 和 __data[4]__ 可以是任意字节，你想设成什么都行。

  3. __data[5]__ 和 __data[6]__ 是Navicat的语言标志，值如下：

     |  语言类型   |  data[5]  |  data[6]  |  发现者         |
     |------------|:---------:|:---------:|-----------------|
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

  4. __data[7]__ 是Navicat产品ID。（感谢 @dragonflylee 和 @Deltafox79提供的数据）

     |产品名                |Enterprise|Standard|Educational|Essentials|
     |---------------------|:--------:|:------:|:---------:|:--------:|
     |Navicat Report Viewer|0x0B      |        |           |          |
     |Navicat Data Modeler |          |0x47    |0x4A       |          |
     |Navicat Premium      |0x65      |        |0x66       |0x67      |
     |Navicat MySQL        |0x68      |0x69    |0x6A       |0x6B      |
     |Navicat PostgreSQL   |0x6C      |0x6D    |0x6E       |0x6F      |
     |Navicat Oracle       |0x70      |0x71    |0x72       |0x73      |
     |Navicat SQL Server   |0x74      |0x75    |0x76       |0x77      |
     |Navicat SQLite       |0x78      |0x79    |0x7A       |0x7B      |
     |Navicat MariaDB      |0x7C      |0x7D    |0x7E       |0x7F      |
     |Navicat MongoDB      |0x80      |0x81    |0x82       |          |

  5. __data[8]__ 的高4位代表 __版本号__。低4位未知，但可以用来延长激活期限，可取的值有`0000`和`0001`。

     例如：

     对于 __Navicat 12__: 高4位必须是`1100`，为`12`的二进制形式。  
     对于 __Navicat 11__: 高4位必须是`1011`，为`11`的二进制形式。  

  6. __data[9]__ 目前暂未知，但如果你想要 __not-for-resale license__ 的话可以设成`0xFD`、`0xFC`或`0xFB`。

     根据 __Navicat 12 for Mac x64__ 版本残留的符号信息可知：

     * `0xFB`是 __Not-For-Resale-30-days__ license.  
     * `0xFC`是 __Not-For-Resale-90-days__ license.  
     * `0xFD`是 __Not-For-Resale-365-days__ license.  
     * `0xFE`是 __Not-For-Resale__ license.  
     * `0xFF`是 __Site__ license.  

  之后Navicat使用 __ECB__ 模式的 __DES__ 算法来加密 __data[10]__ 的后8字节，也就是 __data[2]__ 到 __data[9]__ 的部分。

  相应的DES密钥为：

  ```cpp
  unsigned char DESKey = { 0x64, 0xAD, 0xF3, 0x2F, 0xAE, 0xF2, 0x1A, 0x27 };
  ```

  之后使用Base32编码 __data[10]__，其中编码表改为：

  ```cpp
  char EncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  ```

  编码之后你应该会得到一个16字节长的字符串，并且以"NAV"打头。

  将16字节的字符串分成4个4字节的小块，然后用`"-"`连接就可以得到 __序列号__。

## 2. 激活过程

  1. 检查用户输入的 __序列号__ 是否合法。

  2. 在用户点击了`激活`按钮之后，Navicat会先尝试在线激活。如果失败，用户可以选择离线激活。

  3. Navicat会使用用户输入的 __序列号__ 以及从用户电脑收集来的信息生成 __离线激活请求信息__，然后用 __Navicat激活公钥__ 加密，并将密文用Base64编码，最后得到 __请求码__。

  4. 正常流程下，__请求码__ 应该通过可联网的电脑发送给Navicat的官方激活服务器。之后Navicat的官方激活服务器会返回一个合法的 __激活码__。

     但现在我们使用注册机来扮演官方激活服务器的角色，只是Navicat软件里的激活公钥得换成自己的公钥：

     1. 根据 __请求码__, 获得`"DI"`值和`"K"`值。

     2. 用`"K"`值、用户名、组织名和`"DI"`值填写 __离线激活回复信息__。

     3. 用自己的2048位RSA私钥加密 __离线激活回复信息__，你将会得到256字节的密文。

     4. 用Base64编码这256字节的密文，就可以得到 __激活码__。

     5. 在Navicat软件中填入 __激活码__ 即可完成离线激活。

