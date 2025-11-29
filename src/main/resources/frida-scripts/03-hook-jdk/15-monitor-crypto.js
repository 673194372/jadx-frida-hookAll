/**
 * 【功能】监控 Java 加密架构 (JCA) 的所有加密操作
 * 
 * 【参考】思路参考网上流出的小肩膀自吐算法脚本
 * 
 * 【依赖辅助函数】
 * 加密过程中会用到很多数据转换函数；
 */

// Monitor Java Cryptography Architecture (JCA) operations
// 监控 Java 加密架构 (MessageDigest, Mac, Cipher, Signature)
// 用途：监控所有哈希计算(MD5/SHA)、HMAC签名、AES/RSA加解密
// 逆向价值：★★★★★ 这是定位签名算法、获取加密密钥(Key/IV)的最直接路径
function hook_monitor_crypto() {
    Java.perform(function () {
        const base64EncodeChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        
        function bytesToHex(bytes) {
            var str = '';
            for (var i = 0; i < bytes.length; i++) {
                var k = bytes[i];
                var j = k < 0 ? k + 256 : k;
                str += (j < 16 ? "0" : "") + j.toString(16);
            }
            return str;
        }
        
        function bytesToString(bytes) {
            var str = '';
            bytes = new Uint8Array(bytes);
            for (var i = 0; i < bytes.length; i++) {
                str += String.fromCharCode(bytes[i]);
            }
            return str;
        }
        
        function bytesToBase64(bytes) {
            var result = '';
            var i = 0;
            while (i < bytes.length) {
                var b1 = bytes[i++] & 0xFF;
                var b2 = i < bytes.length ? bytes[i++] & 0xFF : 0;
                var b3 = i < bytes.length ? bytes[i++] & 0xFF : 0;
                
                result += base64EncodeChars.charAt(b1 >> 2);
                result += base64EncodeChars.charAt(((b1 & 0x03) << 4) | (b2 >> 4));
                result += (i - 1 < bytes.length) ? base64EncodeChars.charAt(((b2 & 0x0F) << 2) | (b3 >> 6)) : '=';
                result += (i < bytes.length) ? base64EncodeChars.charAt(b3 & 0x3F) : '=';
            }
            return result;
        }
        
        // Helper: Print Stack Trace
        function showJavaStacks() {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        // ========================================================================
        // 1. MessageDigest (Hash: MD5, SHA-1, SHA-256)
        // ========================================================================
        let MessageDigest = Java.use("java.security.MessageDigest");
        
        // 监控 update (输入数据)
        MessageDigest["update"].overload('[B').implementation = function (input) {
            console.log(`\n[->] MessageDigest.update(byte[]) algo=${this.getAlgorithm()}`);
            console.log(`    ->input(hex)= ${bytesToHex(input)}`);
            console.log(`    ->input(str)= ${bytesToString(input)}`);
            // showJavaStacks();
            return this["update"](input);
        };

        // 监控 digest (输出结果)
        MessageDigest["digest"].overload().implementation = function () {
            let result = this["digest"]();
            console.log(`\n[<-] MessageDigest.digest() algo=${this.getAlgorithm()}`);
            console.log(`    ->result(hex)= ${bytesToHex(result)}`);
            showJavaStacks();
            return result;
        };
        
        // 监控 digest(byte[]) (一次性输入并输出)
        MessageDigest["digest"].overload('[B').implementation = function (input) {
            console.log(`\n[->] MessageDigest.digest(byte[]) algo=${this.getAlgorithm()}`);
            console.log(`    ->input(hex)= ${bytesToHex(input)}`);
            console.log(`    ->input(str)= ${bytesToString(input)}`);
            let result = this["digest"](input);
            console.log(`    ->result(hex)= ${bytesToHex(result)}`);
            showJavaStacks();
            return result;
        };

        // ========================================================================
        // 2. Mac (HMAC)
        // ========================================================================
        let Mac = Java.use("javax.crypto.Mac");
        
        // 监控 init (Key)
        Mac["init"].overload('java.security.Key').implementation = function (key) {
            console.log(`\n[->] Mac.init() algo=${this.getAlgorithm()}`);
            console.log(`    ->key_algo= ${key.getAlgorithm()}`);
            console.log(`    ->key_bytes(hex)= ${bytesToHex(key.getEncoded())}`);
            showJavaStacks();
            return this["init"](key);
        };

        // 监控 update
        Mac["update"].overload('[B').implementation = function (input) {
            // console.log(`[->] Mac.update()`); // 有时候 update 太多，可以注释掉
            return this["update"](input);
        };

        // 监控 doFinal
        Mac["doFinal"].overload().implementation = function () {
            let result = this["doFinal"]();
            console.log(`\n[<-] Mac.doFinal() algo=${this.getAlgorithm()}`);
            console.log(`    ->result(hex)= ${bytesToHex(result)}`);
            showJavaStacks();
            return result;
        };
        
        Mac["doFinal"].overload('[B').implementation = function (input) {
            let result = this["doFinal"](input);
            console.log(`\n[<-] Mac.doFinal(byte[]) algo=${this.getAlgorithm()}`);
            console.log(`    ->input(hex)= ${bytesToHex(input)}`);
            console.log(`    ->input(str)= ${bytesToString(input)}`);
            console.log(`    ->result(hex)= ${bytesToHex(result)}`);
            showJavaStacks();
            return result;
        };

        // ========================================================================
        // 3. SecretKeySpec (密钥规范 - 最重要！)
        // ========================================================================
        let SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, algorithm) {
            console.log("\n╔══════════════════════════════════════");
            console.log("║ [SecretKeySpec] 密钥创建");
            console.log("╠══════════════════════════════════════");
            console.log("║ 算法: " + algorithm);
            console.log("║ 密钥(Hex): " + bytesToHex(keyBytes));
            console.log("║ 密钥(String): " + bytesToString(keyBytes));
            console.log("║ 密钥(Base64): " + bytesToBase64(keyBytes));
            console.log("╚══════════════════════════════════════");
            showJavaStacks();
            return this.$init(keyBytes, algorithm);
        };
        
        // ========================================================================
        // 4. IvParameterSpec (IV 向量 - 关键！)
        // ========================================================================
        let IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
        
        IvParameterSpec.$init.overload('[B').implementation = function (iv) {
            console.log("\n╔══════════════════════════════════════");
            console.log("║ [IvParameterSpec] IV向量创建");
            console.log("╠══════════════════════════════════════");
            console.log("║ IV(Hex): " + bytesToHex(iv));
            console.log("║ IV(String): " + bytesToString(iv));
            console.log("║ IV(Base64): " + bytesToBase64(iv));
            console.log("╚══════════════════════════════════════");
            showJavaStacks();
            return this.$init(iv);
        };
        
        // ========================================================================
        // 5. DESKeySpec (DES 密钥)
        // ========================================================================
        let DESKeySpec = Java.use('javax.crypto.spec.DESKeySpec');
        
        DESKeySpec.$init.overload('[B').implementation = function (keyBytes) {
            const result = this.$init(keyBytes);
            const bytes_key_des = this.getKey();
            console.log("\n╔══════════════════════════════════════");
            console.log("║ [DESKeySpec] DES密钥创建");
            console.log("╠══════════════════════════════════════");
            console.log("║ 密钥(Hex): " + bytesToHex(bytes_key_des));
            console.log("║ 密钥(String): " + bytesToString(bytes_key_des));
            console.log("╚══════════════════════════════════════");
            showJavaStacks();
            return result;
        };
        
        DESKeySpec.$init.overload('[B', 'int').implementation = function (keyBytes, offset) {
            const result = this.$init(keyBytes, offset);
            const bytes_key_des = this.getKey();
            console.log("\n╔══════════════════════════════════════");
            console.log("║ [DESKeySpec] DES密钥创建 (带偏移)");
            console.log("╠══════════════════════════════════════");
            console.log("║ 偏移: " + offset);
            console.log("║ 密钥(Hex): " + bytesToHex(bytes_key_des));
            console.log("║ 密钥(String): " + bytesToString(bytes_key_des));
            console.log("╚══════════════════════════════════════");
            showJavaStacks();
            return result;
        };

        // ========================================================================
        // 6. Cipher (Encryption/Decryption: AES, DES, RSA)
        // ========================================================================
        let Cipher = Java.use("javax.crypto.Cipher");
        
        // 监控 init (Key, IV)
        // 重载较多，这里只监控最常用的
        Cipher["init"].overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (mode, key, params) {
            let modeStr = (mode === 1) ? "ENCRYPT_MODE" : (mode === 2 ? "DECRYPT_MODE" : mode);
            console.log(`\n[->] Cipher.init() algo=${this.getAlgorithm()} mode=${modeStr}`);
            console.log(`    ->key_bytes(hex)= ${bytesToHex(key.getEncoded())}`);
            // 尝试解析 IV (通常 params 是 IvParameterSpec)
            try {
                let IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
                let ivSpec = Java.cast(params, IvParameterSpec);
                console.log(`    ->iv_bytes(hex)= ${bytesToHex(ivSpec.getIV())}`);
            } catch (e) {
                console.log(`    ->params= ${params.toString()}`);
            }
            showJavaStacks();
            return this["init"](mode, key, params);
        };
        
        // 监控 doFinal (加解密结果)
        Cipher["doFinal"].overload('[B').implementation = function (input) {
            let result = this["doFinal"](input);
            console.log(`\n[<-] Cipher.doFinal() algo=${this.getAlgorithm()}`);
            console.log(`    ->input(hex)= ${bytesToHex(input)}`);
            console.log(`    ->input(str)= ${bytesToString(input)}`);
            console.log(`    ->result(hex)= ${bytesToHex(result)}`);
            // showJavaStacks();
            return result;
        };

        // ========================================================================
        // 4. Signature (RSA/DSA Sign)
        // ========================================================================
        let Signature = Java.use("java.security.Signature");
        
        Signature["sign"].overload().implementation = function () {
            let result = this["sign"]();
            console.log(`\n[<-] Signature.sign() algo=${this.getAlgorithm()}`);
            console.log(`    ->signature(hex)= ${bytesToHex(result)}`);
            showJavaStacks();
            return result;
        };
        
        Signature["verify"].overload('[B').implementation = function (signature) {
            let result = this["verify"](signature);
            console.log(`\n[<-] Signature.verify() algo=${this.getAlgorithm()}`);
            console.log(`    ->signature(hex)= ${bytesToHex(signature)}`);
            console.log(`    ->result= ${result}`);
            showJavaStacks();
            return result;
        };

    });
    console.warn(`[*] hook_monitor_crypto is injected!`);
}
hook_monitor_crypto();

/*
关于 Java 加密架构 (JCA) 的详解

Java 提供了一套统一的加密接口，位于 `java.security` 和 `javax.crypto` 包中。
无论底层是用 OpenSSL 还是其他库实现，上层 API 几乎都是一样的。

核心类与逆向价值：

1. MessageDigest (摘要/哈希):
   - 算法：MD5, SHA-1, SHA-256, SHA-512。
   - 特征：不可逆，通常用于签名生成、密码存储。
   - Hook点：`update(input)` 看原文，`digest()` 看结果。

2. Mac (消息认证码):
   - 算法：HmacSHA1, HmacSHA256。
   - 特征：带密钥的哈希。
   - Hook点：`init(key)` 拿密钥！`doFinal(input)` 看原文和签名。

3. Cipher (加解密):
   - 算法：AES, DES, RSA。
   - 特征：可逆。
   - Hook点：
     - `init(mode, key, iv)`: 拿密钥 (Key) 和 偏移量 (IV)！这是破解加密最关键的一步。
     - `doFinal(input)`: 看加密前的明文或解密后的明文。

4. Signature (数字签名):
   - 算法：SHA256withRSA, MD5withRSA。
   - 特征：非对称加密，私钥签名，公钥验签。
   - Hook点：`sign()`。

速记：
1. 只要是标准的 Java 加密，Hook 这几个类绝对能抓到。
2. `Cipher.init` 是获取 AES Key/IV 的神器。
3. 看到乱码？那是加密后的 bytes。看到 hex 字符串？那是转 hex 后的结果。
*/
