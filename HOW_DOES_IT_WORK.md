# Navicat Keygen - How does it work?

[中文版 How does it work?](HOW_DOES_IT_WORK.zh-CN.md)

## 1. Keyword Explanation.

* __Navicat Activation Public Key__

  It is an __RSA-2048__ public key that Navicat used to encrypt or decrypt offline activation information.

  It is stored in 
  
  ```
  Navicat Premium.app/Contents/Resources/rpk
  ```

  You can see it by any kind of text editor. The content is:

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

  If you have the corresponding private key, please tell me. I would be very appreciated for your generous.

  __NOTICE:__

  Start from __Navicat Premuim 12.0.24 for Mac__, the public key is no longer stored in 
  
  ```
  Navicat Premium.app/Contents/Resources/rpk
  ```

  Instead, the public key is stored in Navicat executable file 

  ```
  Navicat Premium.app/Contents/MacOS/Navicat Premium
  ``` 

  in plaintext. You can see it by searching string `"-----BEGIN PUBLIC KEY-----  "`.

  __NOTICE:__

  Start from __Navicat Premium 12.1.14 for Mac__, the public key is still stored in the executable file in plaintext. 
  
  However, it does not load the key from the plaintext. Instead, it loads the key from a piece of ciphertext which is 0x188 bytes long. The ciphertext is

  ```c
  const uint8_t ciphertext[0x188] = {
      0xfe, 0xfd, 0xfc, 0xf4, 0xfe, 0xd2, 0xf8, 0xf4, 0xf1, 0xd3, 0xde, 0xc7, 0xdf, 0xd3, 0xd0, 0xfd,
      0x8a, 0xc3, 0x85, 0xf4, 0xf6, 0xe9, 0xfc, 0xfc, 0xf2, 0xf5, 0xfa, 0xf5, 0xf6, 0xe9, 0x81, 0xfb,
      0xfe, 0xfd, 0xfc, 0xf4, 0xf4, 0xdf, 0xf2, 0xf9, 0xf2, 0xe5, 0xf0, 0xf7, 0xc0, 0x89, 0xdd, 0xcb,
      0xf5, 0x87, 0xe6, 0xdd, 0xf4, 0xd9, 0xf8, 0xfb, 0xde, 0xf9, 0xcf, 0xc5, 0x8f, 0x80, 0x80, 0xf3,
      0xc2, 0xd0, 0xe2, 0x8f, 0xfa, 0x8a, 0xdd, 0xf3, 0xd7, 0xdc, 0x86, 0xdc, 0xf0, 0x81, 0xc0, 0xea,
      0xd0, 0xd9, 0xf9, 0xd8, 0xda, 0xf2, 0xd0, 0xfd, 0xc3, 0xf6, 0xf3, 0x82, 0xf2, 0x81, 0xef, 0xf2,
      0xe0, 0xf9, 0xf2, 0xd3, 0x8f, 0xd7, 0xe9, 0xfb, 0xca, 0x86, 0xde, 0xfc, 0xf3, 0xd5, 0xdd, 0xf4,
      0xc7, 0x80, 0xf7, 0xd5, 0xf2, 0xc1, 0xde, 0xcc, 0xc0, 0xc7, 0xf0, 0xd0, 0xd0, 0xd1, 0xd7, 0xcc,
      0xd2, 0x81, 0xc1, 0x83, 0xdd, 0xd5, 0x8a, 0x8f, 0x81, 0xe1, 0xf4, 0xd9, 0xf3, 0xd7, 0xca, 0xef,
      0xf9, 0xdf, 0xe1, 0xee, 0xf0, 0xe9, 0xd1, 0xca, 0xf2, 0xe3, 0xf8, 0xf0, 0x83, 0xde, 0xfb, 0xd7,
      0xf1, 0xc4, 0xfa, 0x85, 0xf2, 0xdd, 0xdd, 0xfd, 0x85, 0x86, 0xc7, 0xf9, 0xc4, 0xc9, 0xf4, 0xf8,
      0xd4, 0xd9, 0xe6, 0xd2, 0xf6, 0xc1, 0xc1, 0xf9, 0xe0, 0xe4, 0xf7, 0xe4, 0xfd, 0xf1, 0xf6, 0xfc,
      0xe1, 0x84, 0xe4, 0xd1, 0xed, 0xfe, 0xdb, 0xe8, 0xdd, 0xe1, 0x85, 0xd0, 0xc5, 0xd2, 0x8a, 0x8e,
      0xd5, 0xdd, 0xe3, 0xdb, 0xd0, 0xe1, 0xd0, 0xf6, 0xc6, 0xee, 0xe6, 0xf7, 0xda, 0xf1, 0xdb, 0xc9,
      0x8b, 0xee, 0xcd, 0xdf, 0xff, 0xe8, 0xdd, 0xca, 0x82, 0xdb, 0xf1, 0x82, 0xc3, 0xed, 0xc9, 0xcc,
      0xc0, 0xf2, 0xd6, 0xdf, 0x83, 0xe9, 0xf3, 0xce, 0xea, 0xfa, 0xdf, 0xf8, 0xd9, 0xff, 0xec, 0x88,
      0xe4, 0xe4, 0xfd, 0x80, 0xc5, 0xce, 0xfa, 0xd2, 0xf4, 0xd8, 0x84, 0xff, 0xe5, 0xf3, 0xcb, 0xc2,
      0xfe, 0xc0, 0xc4, 0xfa, 0xde, 0xdd, 0xd5, 0xc9, 0xc5, 0xd5, 0xdf, 0xe3, 0xdd, 0xc1, 0xcb, 0xdd,
      0xfc, 0xf7, 0x83, 0xf8, 0xda, 0xc1, 0xd4, 0xe3, 0xfe, 0xc2, 0xef, 0xf8, 0xf2, 0xea, 0x8a, 0xd2,
      0xc7, 0xf2, 0xf0, 0xc2, 0xfb, 0x89, 0xdc, 0xeb, 0xd1, 0xf7, 0xcc, 0xe2, 0xd1, 0xfc, 0xd4, 0xce,
      0xea, 0xcd, 0xe4, 0x87, 0xe0, 0xcc, 0x8d, 0xf5, 0xc7, 0x85, 0x87, 0xda, 0xcf, 0xde, 0x89, 0xcd,
      0xe5, 0xfd, 0xe7, 0x83, 0xda, 0xdb, 0xfe, 0xf4, 0x84, 0xec, 0xf6, 0xee, 0xfd, 0xea, 0xf1, 0xf5,
      0xf5, 0xfc, 0xe6, 0xd0, 0x86, 0xdf, 0xc3, 0xe2, 0xe4, 0xd5, 0xd7, 0xe4, 0xe4, 0xce, 0xd4, 0xce,
      0x82, 0xda, 0xc7, 0xda, 0x80, 0xcb, 0xee, 0x8c, 0xd0, 0xde, 0xcd, 0xda, 0xdd, 0xcd, 0xcc, 0xeb,
      0xd2, 0xc3, 0xfc, 0xf2, 0xf6, 0xe9, 0xf8, 0xf8
  };
  ```

  The ciphertext is encrypted by XOR encryption where XOR key is 
  
  ```
  \xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba
  ```

* __Request Code__

  It is a Base64 string that represents 256-bytes-long data, while the 256-bytes-long data is the ciphertext of __Offline Activation Request Information__ encrypted by __Navicat Activation Public Key__.

* __Offline Activation Request Information__

  It is just a JSON-style UTF-8 string which contains 3 items. Respectively they are `"K"`, `"DI"` and `"P"`, which represent __snKey__, __DeviceIdentifier__, __Platform__.

  Example:  

  ```
  { "K": "xxxxxxxxxxxxxxxx", "P": "Mac 10.13", "DI": "xxxxxxxxxxxxxxxxxxxx" }
  ```  

* __Activation Code__

  It is a Base64 string that represents 256-bytes-long data, while the 256-bytes-long data is the ciphertext of __Offline Activation Response Information__ encrypted by __Navicat Activation Private Key__ which, so far, we don't know.

* __Offline Activation Response Information__

  Just like __Offline Activation Request Information__, it is also a JSON-style UTF-8 string. But it contains 5 items. Respectively they are `"K"`, `"N"`, `"O"`, `"T"`, '`DI`'.

  `"K"` and `"DI"` has the same meaning mentioned in __Offline Activation Request Information__ and must be same with the corresponding items in __Offline Activation Request Information__.

  `"N"`, `"O"`, `"T"` represent __Name__, __Organization__, __Time__ respectively. __Name__ and __Organization__ are string and the type of __Time__ can be string or integer (Thanks for discoveries from @Wizr, issue #10).

  Differ from Navicat Windows version, `"T"` is mandatory and must have -1 ~ +4 days difference from current time. 
  
  Example:

  ```
  {  
    "DI" : "xxxxxxxxxxxxxxxxxxxx",  
    "T" : "1515770827.925012",  
    "K" : "xxxxxxxxxxxxxxxx",  
    "N" : "DoubleLabyrinth",  
    "O" : "Shadow"  
  }
  ```  

* __snKey__

  It is a 4-block-long string, while every block is 4-chars-long.

  __snKey__ is generated by 10-bytes-long data. In order to explain it easily, I use __uint8_t data[10]__ to represent the 10-bytes-long data.

  1. __data[0]__ and __data[1]__ must be `0x68` and `0x2A` respectively.

     These two bytes are Naivcat signature number.

  2. __data[2]__, __data[3]__ and __data[4]__ can be any byte. Just set them whatever you want.

  3. __data[5]__ and __data[6]__ are related with your Navicat product language.

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

  4. __data[7]__ is Navicat product ID. (Thanks @dragonflylee and @Deltafox79)

     |Product Name         |Enterprise|Standard|Educational|Essentials|
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

  5. High 4 bits of __data[8]__ represents __major version number__. 
   
     Low 4 bits is unknown, but we can use it to delay activation deadline. Possible values are `0000` or `0001`.

     __Example:__

     For __Navicat 12 x64__: High 4 bits must be `1100`, which is the binary of number `12`.  
     For __Navicat 11 x64__: High 4 bits must be `1011`, which is the binary of number `11`.  

  6. __data[9]__ is unknown, but you can set it by `0xFD`, `0xFC` or `0xFB` if you want to use __not-for-resale license__.

     According to symbol information in __Navicat 12 for Mac x64__ version:

     * `0xFB` is __Not-For-Resale-30-days__ license.  
     * `0xFC` is __Not-For-Resale-90-days__ license.  
     * `0xFD` is __Not-For-Resale-365-days__ license.  
     * `0xFE` is __Not-For-Resale__ license.  
     * `0xFF` is __Site__ license.  

  After that. Navicat use __DES__ with __ECB mode__ to encrypt the last 8 bytes which are from __data[2]__ to __data[9]__.

  The DES key is:

  ```cpp
  const uint8_t DESKey = { 0x64, 0xAD, 0xF3, 0x2F, 0xAE, 0xF2, 0x1A, 0x27 };
  ```

  Then use Base32 to encode `uint8_t data[10]` whose encode table is

  ```cpp
  // Thanks for discoveries from @Wizr, issue #10
  char EncodeTable[] = "ABCDEFGH8JKLMN9PQRSTUVWXYZ234567";
  ```

  After encoding, you will get a 16-char-long string starting with `"NAV"`.

  Finally, divide the 16-char-long string to four 4-chars-long blocks and join them with `"-"` then you will get __snKey__.

## 2. Activation Process

1. Check whether __snKey__ that user inputs is valid.

2. After user clicks `Activate`, Navicat will start online activation first. If fails, user can choose offline activation.

3. Navicat will use the __snKey__ that user inputs and some information collected from user's machine to generate __Offline Activation Request Information__. Then Navicat will encrypt it by __Navicat Activation Public Key__ and return a Base64-encoded string as __Request Code__.

4. In legal way, the __Request Code__ should be sent to Navicat official activation server by a Internet-accessible computer. And Navicat official activation server will return a legal __Activation Code__.

But now, we use keygen to play the official activation server's role.

1. According to the __Request Code__, get `"DI"` value and `"K"` value.

2. Fill __Offline Activation Response Information__ with `"K"` value, name, organization name, `"DI"` value and `"T"` value. 

3. Encrypt __Offline Activation Response Information__ by __Navicat Activation Private Key__ and you will get 256-byte-long data.

4. Encode the 256-byte-long data by Base64. The result is __Activation Code__.

5. After user input __Activation Code__, offline activation is done successfully.

