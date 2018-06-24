# Navicat Keygen

  这份repo将会告诉你Navicat是怎么完成离线激活的。

## 1. 关键词解释

  * __Navicat激活公钥__

    这是一个2048位的RSA公钥，Navicat使用这个公钥来完成相关激活信息的加密和解密。

    这个公钥储存在 __Navicat Premium.app/Contents/Resources/rpk__ 中，你可以用任何一种文本编辑器打开并查看它。这个公钥的具体内容为：

    > -----BEGIN PUBLIC KEY-----  
    > MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I  
    > qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv  
    > a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF  
    > R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2  
    > WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt  
    > YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ  
    > awIDAQAB  
    > -----END PUBLIC KEY-----  

    如果您有相应的私钥并乐意公开的话欢迎联系我，我将非常感谢您的慷慨。

    __注意：__

    从 __Navicat Premium for Mac 12.0.24__ 开始，公钥不再存储在 __Navicat Premium.app/Contents/Resources/rpk__ 中。事实上，公钥放在了Navicat的二进制执行文件 __Navicat Premium.app/Contents/MacOS/Navicat Premium__ 中，你可以通过搜索`"-----BEGIN PUBLIC KEY-----"`来找到它。

  * __请求码__

    这是一个Base64编码的字符串，代表的是长度为256字节的数据。这256字节的数据是 __离线激活请求信息__ 被 __Navicat激活公钥__ 加密的密文。

  * __离线激活请求信息__

    这是一个JSON风格的字符串。它包含了3个Key：`"K"`、`"DI"`和`"P"`，分别代表 __序列号__、__设备识别码__（与你的电脑硬件信息相关）和 __平台__ (其实就是操作系统类型)。

    例如：  
    > {  
    > &nbsp;&nbsp;&nbsp;&nbsp;"K": "xxxxxxxxxxxxxxxx",  
    > &nbsp;&nbsp;&nbsp;&nbsp;"P": "Mac 10.13",  
    > &nbsp;&nbsp;&nbsp;&nbsp;"DI": "xxxxxxxxxxxxxxxxxxxx"  
    > }

  * __激活码__

    这是一个Base64编码的字符串，代表的是长度为256字节的数据。这256字节的数据是 __离线激活回复信息__ 被 __Navicat激活私钥__ 加密的密文，目前我们不知道官方的 __Navicat激活私钥__。

  * __离线激活回复信息__

    和 __离线激活请求信息__ 一样，它也是一个JSON风格的字符串。但是它包含5个Key，分别为`"K"`、`"N"`、`"O"`、`"T"`和`"DI"`.

    `"K"` 和 `"DI"` 的意义与 __离线激活请求信息__ 中的相同，且Value必须与 __离线激活请求信息__ 中的相同。

    `"N"`、`"O"`、`"T"` 分别代表 __注册名__、__组织__、__授权时间__。__注册名__ 和 __组织__ 的值类型为字符串，__授权时间__ 的值类型可以为字符串或整数（感谢@Wizr在issue #10的报告）。

    与Windows版本不同的是，`"T"`是必须的，且代表的时间必须位于当前时间-1 ~ +4天之内。下面是一个 __离线激活回复信息__ 的示例：

    > {  
    > &nbsp;&nbsp;&nbsp;&nbsp;"DI" : "xxxxxxxxxxxxxxxxxxxx",  
    > &nbsp;&nbsp;&nbsp;&nbsp;"T" : "1515770827.925012",  
    > &nbsp;&nbsp;&nbsp;&nbsp;"K" : "xxxxxxxxxxxxxxxx",  
    > &nbsp;&nbsp;&nbsp;&nbsp;"N" : "DoubleLabyrinth",  
    > &nbsp;&nbsp;&nbsp;&nbsp;"O" : "Shadow"  
    > }  

  * __序列号__

    这是一个被分为了4个部分的字符串，其中每个部分都是4个字符长。

    __序列号__ 是通过10个字节的数据来生成的。为了表达方便，我用 __data[10]__ 来表示这10个字节。

    1. __data[0]__ 和 __data[1]__ 必须分别为 `0x68` 和 `0x2A`。

       _`Navicat产品类型变化时，这两个值可能会变。目前暂未确认。`_  

    2. __data[2]__、__data[3]__ 和 __data[4]__ 可以是任意字节，你想设成什么都行。

    3. __data[5]__ 和 __data[6]__ 与你Navicat的语言有关，值如下：

       |  语言类型   |  data[5]  |  data[6]  |  发现者         |
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

       根据 __Navicat 12 for Mac x64__ 版本残留的符号信息可知这两个字节为 __Product Signature__。

    4. __data[7]__ 指示这是 __commercial license__ 还是 __non-commercial license__。

       对于 __Navicat 12__: `0x65`是 __commercial license__，`0x66`是 __non-commercial license__。  
       对于 __Navicat 11__: `0x15`是 __commercial license__，`0x16`是 __non-commercial license__。  

       _`Navicat产品类型变化时，这两个值可能会变。目前暂未确认。`_  

       根据 __Navicat 12 for Mac x64__ 版本残留的符号信息可知：__commercial license__ 是 __Enterprise License__， __non-commercial license__ 是 __Educational License__。

    5. __data[8]__ 的高4位代表 __版本号__。低四位未知，但可以用来延长激活期限，可取的值有`0000`和`0001`。

       对于 __Navicat 12__: 高4位必须是`1100`，为`12`的二进制形式。  
       对于 __Navicat 11__: 高4位必须是`1011`，为`11`的二进制形式。  

    6. __data[9]__ 目前暂未知，但如果你想要 __not-for-resale license__ 的话可以设成`0xFD`、`0xFC`或`0xFB`。这个值一定不能是`0x00`,其他值随便。

       根据 __Navicat 12 for Mac x64__ 版本残留的符号信息可知：

       * `0xFB`是 __Not-For-Resale-30-days__ license.  
       * `0xFC`是 __Not-For-Resale-90-days__ license.  
       * `0xFD`是 __Not-For-Resale-365-days__ license.  
       * `0xFE`是 __Not-For-Resale__ license.  
       * `0xFF`是 __Site__ license.  

    -----------------

    之后Navicat使用 __ECB__ 模式的 __DES__ 算法来加密 __data[10]__ 的后8字节，也就是 __data[2]__ 到 __data[9]__ 的部分。

    相应的DES密钥为：

    ```cpp
    unsigned char DESKey = { 0x64, 0xAD, 0xF3, 0x2F, 0xAE, 0xF2, 0x1A, 0x27 };
    ```

    之后编码 __data[10]__：

    1. 将 __data[10]__ 视作为一个80位长的数据。

       如果 __data[10]__ 以`0x68`和`0x2A`开始的话，80位长的数据应该为`01011000 00101010......`

    2. 将80位长的数据分为16个5位长的块。

       如果 __data[10]__ 以`0x68`和`0x2A`开始的话，16个5位长的块应为`01011`、 `00000`、`10101`、`0....`

    3. 这样每一块的值就会小于32。将它们通过下表编码：

       ```cpp
       // Thanks for discoveries from @Wizr, issue #10
       char EncodeTable[] = "ABCDEFGH8JKLMN9PQRSTUVWXYZ234567";
       ```

       你就会得到一个16字节的字符串。

       如果 __data[10]__ 以`0x68`和`0x2A`开始的话，编码之后应该以`"N"`、`"A"`、`"V"`打头。

    4. 将16字节的字符串分成4个4字节的小块，然后用`"-"`连接就可以得到 __序列号__。

## 3. 激活过程

  1. 检查用户输入的 __序列号__ 是否合法。

  2. 在用户点击了`激活`按钮之后，Navicat会先尝试在线激活。如果失败，用户可以选择离线激活。

  3. Navicat会使用用户输入的 __序列号__ 以及从用户电脑收集来的信息生成 __离线激活请求信息__，然后用 __Navicat激活公钥__ 加密，并将密文用Base64编码，最后得到 __请求码__。

  4. 正常流程下，__请求码__ 应该通过可访问Internet的电脑发送给Navicat的官方激活服务器。之后Navicat的官方激活服务器会返回一个合法的 __激活码__。

     但现在我们使用注册机来扮演官方激活服务器的角色，只是Navicat软件里的激活公钥得换成自己的公钥：

     1. 根据 __请求码__, 获得`"DI"`值和`"K"`值。

     2. 用`"K"`值、用户名、组织名和`"DI"`值填写 __离线激活回复信息__。

     3. 用自己的2048位RSA私钥加密 __离线激活回复信息__，你将会得到256字节的密文。

     4. 用Base64编码这256字节的密文，就可以得到 __激活码__。

     5. 在Navicat软件中填入 __激活码__ 即可完成离线激活。

## 4. 如何编译

  * 在编译之前，你应该确保你安装了OpenSSL。如果你有`brew`的话，你可以通过`brew install openssl`来完成OpenSSL的安装。

    ```bash
    $ cd navicat-keygen
    $ make release
    ```

  * 如果你的Navicat版本号等于或大于12.0.24，你需要编译patcher。

    ```bash
    $ cd navicat-patcher
    $ make release
    ```

  注意：

  对于Navicat版本号等于或大于12.0.24的，如果你想要使用自己的RSA密钥，请在编译patcher之前替换掉`navicat-patcher/main.c`里下面的内容

  ```cpp
  const char pubkey[9][72] = {
  "-----BEGIN PUBLIC KEY-----",
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxqkTcfbKw8ysVygePlcB",
  "oUAhCF6oniyP13iDtu85ZsHwqw8PnMyTp6n6FnMN9YinleIAy6NFveBu/vshTN8S",
  "oXbYyy5AqdZ8CQpfvuriO9UNfgV1l7SFdPPpruFAmOw+uzA3GawMsg3QNK/htqJe",
  "b4xKHFS04xC2AueE2RTmk6tJcL8TEBfRG7DEYOHPjebKl1NQ3ZIu15U97cCPYKO2",
  "pWHzsb+Fr4Wj0DChLoxlXxaBcJ2ozogaq0tW2t4Aopvt9kRSuSK9HcgxICJM5ct4",
  "naU91WFGWlw0+0JpiMIl5OnMbpak/5xQre9DL8zM8LjRy14I88txvXvhPEsWaYCO",
  "1QIDAQAB",
  "-----END PUBLIC KEY-----"
  };
  ```

  为你自己的RSA公钥。

## 4. 如何使用这个Keygen

  1. 编译好keygen。

  2. 生成2048位的RSA密钥对。__（仅限Navicat Premium版本号小于12.0.24）__  

     ```bash
     $ openssl genrsa -out 2048key.pem 2048
     $ openssl rsa -in 2048key.pem -pubout -out rpk
     ```

     你会得到两个文件：`2048key.pem`和`rpk`。

     __现在你们可以不用生成RSA密钥了，我已经准备好了这两个文件：__

       * `rpk`文件在`navicat-patcher`文件夹中。

       * `2048key.pem`在`navicat-keygen`文件夹中。

  3. 对于Navicat Premium版本 < 12.0.24的：

       * 用生成或提供的`rpk`文件替换掉`Navicat Premium.app/Contents/Resources/rpk`。

     对于Navicat Premium版本 >= 12.0.24的：

       * 备份好`Navicat Premium.app/Contents/MacOS/Navicat Premium`文件，__以及Navicat中所有的数据库连接配置信息（包括密码）__。

       * 删掉`Keychain.app`中所有由Navicat保存的密码。

       * 运行patcher：

         ```bash
         $ cd navicat-patcher
         $ ./navicat-patcher <your navicat executable file path>
         ```

         例如：

         ```bash
         $ cd navicat-patcher
         $ ./navicat-patcher /Applications/Navicat\ Premium.app/Contents/MacOS/Navicat\ Premium
         ```

       * __生成一个自签名的代码签名证书，并在`Keychain.app`中总是信任它。然后使用`codesign`命令对`Navicat Premium.app`进行重签名。这一步非常重要。__

         ```bash
         $ codesign -f -s "Your self-signed code-sign certificate name" <path to Navicat Premium.app>
         ```

  4. 接下来，打开`Terminal.app`，并定位到`navicat-keygen`文件夹：

     ```bash
     $ ./navicat-keygen 2048key.pem
     ```

     接下来你会被要求输入Navicat的语言版本，然后得到一个 __序列号__，同时keygen会要求你输入用户名和组织名。  
     直接填写，之后你会被要求填写你得到的 __请求码__。注意此时 __不要关闭Terminal__.

  5. 打开Navicat Premium。找到`注册`按钮并点击，在弹出的窗口中填入keygen给你的 __序列号__。然后点击`激活`按钮。

  6. 一般来说在线激活肯定会失败，这时候Navicat会询问你是否`手动激活`，直接选吧。

  7. 在`手动激活`窗口你会得到一个请求码，复制它并把它粘贴到keygen里。最后别忘了连按至少两下回车结束输入。

  8. 如果不出意外，你会得到一个看似用Base64编码的 __激活码__。直接复制它，并把它粘贴到Navicat的`手动激活`窗口，最后点`激活`按钮。如果没什么意外的话应该能成功激活。

  9. 最后，如果你备份了数据库连接配置信息，那么恢复它把。
