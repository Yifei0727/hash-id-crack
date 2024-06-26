## 数据哈希查找工具

哈希(Hash) 也称摘要(Digest)、散列或者杂凑算法，是一种从任意数据中创建固定长度散列值的方法。
多用于文件存储（如Git），密码存储(PBKDF)，常用于数据完整性校验(Hash based Mac)等场景。
虽然哈希算法是一种单向函数（即无法通过哈希值逆向推导出原始数据），但是可以通过穷举法、彩虹表等方式找到原始数据。

### 1. 项目简介

某些系统为了避免敏感数据直接存储，选择采用哈希算法对数据处理后将哈希值存储，但是某些原因又需要快速找到其原始数据，本工具用于根据已知的原始数据快速查找哈希值的原始数据。

### 2. 使用方法

#### 2.1. 依赖环境

请下载对应环境编译的可执行文件或者自行编译。

#### 2.2 执行说明

```shell
./hash-id-crack -f <dict_file> -e <hash_file> [--hash <hash_name>]
```

- `dict_file`：字典数据文件，每行一个原始数据（邮箱、手机号、ID）等，是系统已知的数据集合。
- `hash_file`：哈希结果文件，每行一个要查找的哈希值（Hex格式），是需要查找的目标哈希值集合。
- `hash`：哈希算法名称，可选参数，支持的哈希算法有：`md5`、`sha1`、`sha256`、`sha512` 等，默认为`sm3`。

### 3. 安全建议

1. **不要**直接只使用一次哈希算法对特殊性用户标识数据的邮箱、手机号等进行处理后就对哈希值落库，难以对抗彩虹表攻击。这种方式只会麻烦自己，实际上并不会增加安全性
2. 对用户标识数据进行处理时，建议系统为每个用户产生其私有的盐值，同时要保证盐值的安全性
3. 对于落库的敏感数据，建议使用对称加密算法进行加密后再存储，保证数据的安全性