# ML-KEM-SSL 抗量子加密通信系统 使用指南
## 一、前置准备：生成合规SSL证书
OpenSSL 3.0+（含3.6.0）对证书安全等级有严格限制，需生成4096位RSA证书避免报错，生成后自动适配项目，无需手动调整路径。

### 1. WSL/Linux 环境（推荐，适配性最佳）
```bash
# 进入项目根目录
cd /mnt/c/Users/22126/CLionProjects/MLkem
# 一键删除旧证书、生成新证书（有效期10年，无交互）
rm -rf cert && mkdir -p cert && openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout cert/key.pem -out cert/cert.pem -subj "/CN=127.0.0.1"
# 赋予证书可读权限，解决Linux权限问题
chmod -R 755 cert && chmod 644 cert/*.pem
```

### 2. Windows 环境（MinGW/MSVC通用）
打开CMD终端，进入项目根目录执行：
```cmd
rd /s /q cert && mkdir cert
openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout cert/key.pem -out cert/cert.pem -subj "/CN=127.0.0.1"
```

## 二、编译方式（两种方案，按需选择）
### 方案1：CMake + CLion 一键编译（推荐，零配置）
1. 打开CLion，导入项目根目录，自动加载`CMakeLists.txt`配置；
2. 右上角选择编译配置：`Debug-MinGW`/`Debug-MSVC`/`Debug-WSL`（对应你的环境）；
3. 点击【锤子图标】编译，完成后可执行文件生成在对应编译目录（如`cmake-build-debug-wsl`）；
4. 核心优势：自动拷贝证书和依赖库，无需手动处理路径/依赖。

### 方案2：原生命令行编译（无IDE环境适用）
```bash
# Linux/WSL 编译（C++20标准，链接必要系统库）
g++ -std=c++20 *.cpp -o MLkem -loqs -lcrypto -lpthread -ldl

# Windows (MinGW) 编译（链接Windows套接字库）
g++ -std=c++20 *.cpp -o MLkem.exe -loqs -lcrypto -lws2_32
```

## 三、运行指南（核心步骤，必按顺序执行）
### 运行须知
1.  必须先启动服务端，再启动客户端；
2.  默认连接地址：`127.0.0.1:8888`，证书已自动拷贝至运行目录，无需额外配置。

### 1. 查看帮助信息
```bash
# Linux/WSL
./MLkem -help

# Windows
./MLkem.exe -help
```

### 2. 启动服务端（无参数，极简启动）
```bash
# Linux/WSL（进入编译目录后执行）
cd cmake-build-debug-wsl && ./MLkem server

# Windows（进入编译目录后执行）
cd cmake-build-debug-mingw && MLkem.exe server

# CLion：运行配置添加参数「server」，直接点击运行
```
启动成功日志：`[加密成功] 证书加载成功！[服务端] 启动成功，监听端口 8888...`

### 3. 启动客户端（两种方式，二选一）
#### 方式1：默认算法启动（ML-KEM-768，推荐）
```bash
# Linux/WSL
./MLkem client

# Windows
MLkem.exe client
```

#### 方式2：指定算法启动（免编译切换，传参即可）
```bash
# Linux/WSL 示例（三种算法任选）
./MLkem client ML-KEM-512
./MLkem client ML-KEM-768
./MLkem client ML-KEM-1024

# Windows 示例（三种算法任选）
MLkem.exe client ML-KEM-1024

# 连接成功后提示可与服务器进行沟通输入quit退出
```
启动成功日志：`[客户端] 连接服务端成功！[客户端] ML-KEM算法协商完成，建立抗量子加密通信！`

## 四、配置调整（按需自定义）
### 1. 修改通信端口
1.  打开`common.h`文件；
2.  找到`#define SERVER_PORT 8888`，修改端口号即可，全项目自动适配。

### 2. 调整证书路径
1.  打开`common.h`文件；
2.  修改`CERT_FILE`（证书路径）和`KEY_FILE`（私钥路径）宏定义，例如：
    ```cpp
    #define CERT_FILE "custom_cert/cert.pem"
    #define KEY_FILE "custom_cert/key.pem"
    ```
3.  确保新路径下有合规证书，CMake会自动拷贝至编译目录。

## 五、常见问题排查
1.  报错`ee key too small`：重新执行“前置准备”步骤，确保生成4096位证书，且已覆盖至编译目录；
2.  报错`证书加载失败: No such file or directory`：进入编译目录，执行`cp -f ../cert/* cert/`手动拷贝证书；
3.  Windows运行闪退（缺失DLL）：使用CLion编译，自动拷贝依赖库；或手动将vcpkg安装目录下的`libcrypto.dll`、`libssl.dll`、`liboqs.dll`拷贝至可执行文件同级目录；
4.  WSL权限报错`Permission denied`：执行`chmod +x MLkem`赋予程序运行权限，再执行`chmod -R 755 cert`修复证书权限。 