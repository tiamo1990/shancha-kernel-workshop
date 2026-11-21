# 源码

| 目录 | 内容 |
|---|---|
| `payload/own137.c` | 链路载荷源码（自有日志语法、六段流程、成功后 `pause()` 保活） |
| `payload/ksyms_table.h` | 225 项内核符号表（本内核已全量审计） |
| `app/` | 配套 App 的 Java 源码与 Manifest（Shizuku 投递、双载荷路由、界面叙述层） |

## 编译（载荷）

```bash
NDK=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin
$NDK/aarch64-linux-android35-clang \
  -std=gnu11 -O2 -static -pthread -D_GNU_SOURCE \
  own137.c -o own137
$NDK/llvm-strip --strip-all own137
```

宽窗编译选项（回退到更宽松的等待窗口）：

```bash
-DOWN136_R4_WIDE=1
```

## 编译（App）

无 Gradle，使用 aapt2 + javac + d8 + apksigner：

```bash
aapt2 compile --dir res -o out/res.zip
aapt2 link -o out/base.apk -I android.jar --manifest AndroidManifest.xml -A assets --java gen out/res.zip
javac -classpath "$LIBS:android.jar" -d classes $(find src gen -name '*.java')
d8 --lib android.jar --min-api 23 --output dex $(find classes -name '*.class')
# 打包 zip → zipalign -p 4 → apksigner sign
```