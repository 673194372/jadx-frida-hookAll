// Universal SSL Pinning Bypass
// 通用 SSL 证书绑定绕过
// 核心思路：
// 1. Hook TrustManager，让其信任所有证书。
// 2. Hook SSLContext，用我们不安全的 TrustManager 初始化它。
// 3. Hook HostnameVerifier，允许所有主机名。
// 4. Hook CertificatePinner (OkHttp)，阻止其检查逻辑。

function hook_bypass_ssl_pinning() {
    Java.perform(function () {
        // 需要参考网上的脚本 还有 算法助手的xp代码

        console.warn("[*] Universal SSL Pinning Bypass injected successfully!");
    });
}

hook_bypass_ssl_pinning();

/*
关于 SSL Pinning (证书绑定) 的详解

原理：
App 内部硬编码了服务端的证书（或公钥哈希）。
在建立 HTTPS 连接时，App 不仅校验系统根证书，还会比对服务端证书是否与硬编码的一致。
如果不一致（比如被 Charles/Fiddler 抓包时，证书变成了代理软件的证书），App 就会断开连接。

绕过核心：
1. 让 `TrustManager` (信任管理器) 变成“瞎子”，无论给什么证书都说 Valid。
2. 让 `CertificatePinner` (证书绑定器) 变成“哑巴”，不抛出异常。

常见坑：
- Android 7.0+ 默认不信任用户安装的证书。这个脚本通过替换 `SSLContext` 的 `TrustManager` 解决了这个问题。
- 有些 App 使用 Native 层 (OpenSSL/BoringSSL) 验证证书，这个脚本（Java层）无效，需要用 Frida Hook Native 函数。
*/
