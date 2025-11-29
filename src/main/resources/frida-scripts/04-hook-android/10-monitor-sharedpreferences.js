// Monitor SharedPreferences and ContentResolver
// 监控 SharedPreferences 读写和 ContentResolver 数据访问
// 逆向价值：监控本地存储（Token/配置）和隐私数据访问（通讯录/短信）
function hook_monitor_SharedPreferences() {
    Java.perform(function() {
        
        // 堆栈打印辅助函数（可选，调试时打开）
        function showJavaStacks() {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        
        // ========================================================================
        // 1. Hook SharedPreferences 写入操作（EditorImpl）
        // ========================================================================
        try {
            var EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
            
            EditorImpl.putString.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
                console.log("[SP.putString] " + key + " = " + value);
                // showJavaStacks();  // 需要时取消注释
                return this.putString(key, value);
            };
            
            EditorImpl.putInt.overload('java.lang.String', 'int').implementation = function(key, value) {
                console.log("[SP.putInt] " + key + " = " + value);
                return this.putInt(key, value);
            };
            
            EditorImpl.putBoolean.overload('java.lang.String', 'boolean').implementation = function(key, value) {
                console.log("[SP.putBoolean] " + key + " = " + value);
                return this.putBoolean(key, value);
            };
            
            EditorImpl.putFloat.overload('java.lang.String', 'float').implementation = function(key, value) {
                console.log("[SP.putFloat] " + key + " = " + value);
                return this.putFloat(key, value);
            };
            
            EditorImpl.putLong.overload('java.lang.String', 'long').implementation = function(key, value) {
                console.log("[SP.putLong] " + key + " = " + value);
                return this.putLong(key, value);
            };
            
            console.log("[*] SharedPreferences.Editor hooked");
        } catch (e) {
            console.warn("[!] SharedPreferencesImpl$EditorImpl hook failed: " + e);
        }
        
        // ========================================================================
        // 2. Hook SharedPreferences 读取操作（SharedPreferencesImpl）
        // ========================================================================
        try {
            var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
            
            SharedPreferencesImpl.getString.implementation = function(key, defValue) {
                var result = this.getString(key, defValue);
                console.log("[SP.getString] " + key + " = " + result);
                return result;
            };
            
            SharedPreferencesImpl.getInt.implementation = function(key, defValue) {
                var result = this.getInt(key, defValue);
                console.log("[SP.getInt] " + key + " = " + result);
                return result;
            };
            
            SharedPreferencesImpl.getBoolean.implementation = function(key, defValue) {
                var result = this.getBoolean(key, defValue);
                console.log("[SP.getBoolean] " + key + " = " + result);
                return result;
            };
            
            console.log("[*] SharedPreferences read hooked");
        } catch (e) {
            console.warn("[!] SharedPreferencesImpl hook failed: " + e);
        }

        // ========================================================================
        // 3. Hook ContentResolver（内容提供者 - 监控隐私数据访问）
        // ========================================================================
        try {
            var ContentResolver = Java.use("android.content.ContentResolver");
    
            ContentResolver.insert.overload("android.net.Uri", "android.content.ContentValues").implementation = function(uri, values) {
                console.log("[ContentResolver.insert] Uri: " + uri + "  Values: " + values);
                return this.insert(uri, values);
            };
            
            ContentResolver.delete.overload("android.net.Uri", "java.lang.String", "[Ljava.lang.String;").implementation = function(uri, where, selectionArgs) {
                console.log("[ContentResolver.delete] Uri: " + uri);
                return this.delete(uri, where, selectionArgs);
            };
            
            ContentResolver.update.overload('android.net.Uri', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;').implementation = function(uri, values, where, selectionArgs) {
                console.log("[ContentResolver.update] Uri: " + uri);
                return this.update(uri, values, where, selectionArgs);
            };

            ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function(uri, projection, queryArgs, cancellationSignal) {
                console.log("[ContentResolver.query] Uri: " + uri);
                return this.query(uri, projection, queryArgs, cancellationSignal);
            };
            
            ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
                console.log("[ContentResolver.query] Uri: " + uri);
                return this.query(uri, projection, selection, selectionArgs, sortOrder);
            };
            
            ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(uri, projection, selection, selectionArgs, sortOrder, cancellationSignal) {
                console.log("[ContentResolver.query] Uri: " + uri);
                return this.query(uri, projection, selection, selectionArgs, sortOrder, cancellationSignal);
            };
            
            console.log("[*] ContentResolver hooked");
        } catch (e) {
            console.warn("[!] ContentResolver hook failed: " + e);
        }
        
    });
    console.warn("[*] hook_monitor_SharedPreferences is injected!");
}
hook_monitor_SharedPreferences();

/*
关于 Android 存储监控 (SharedPreferences & ContentResolver) 的详解

本脚本监控两种数据存储/共享方式：

1. SharedPreferences (SP):
   - 轻量级 Key-Value 存储，底层是 XML 文件
   - 路径：`/data/data/包名/shared_prefs/`
   - 实现类：`android.app.SharedPreferencesImpl$EditorImpl`
   
   逆向价值：
   - 敏感信息泄露：Token, SessionId, UserID 明文存储
   - 功能开关：is_vip, show_ads, debug_mode
   - 设备指纹：UUID/GUID 持久化保存
   
   典型场景：
   - `putString("token", ...)` → 登录 Token
   - `getBoolean("is_vip")` → 会员状态（可修改返回值破解）
   - `putString("device_id", ...)` → 设备唯一标识

2. ContentResolver (内容提供者):
   - Android 四大组件之一 ContentProvider 的客户端
   - 用途：App 内部或跨 App 共享数据
   - URI 格式：`content://authority/path`
   
   逆向价值：
   - 隐私监控：读取通讯录、短信、相册
   - 跨进程通信：监控 IPC 数据流动
   - 加固对抗：某些壳通过 Provider 传递解密后的 Dex
   
   典型场景：
   - `content://com.android.contacts/...` → 读取通讯录
   - `content://sms/...` → 读取短信验证码
   - `content://media/...` → 访问相册

使用技巧：
1. 初步分析：运行脚本，看 SP 里存了什么
2. 破解会员：找到 `getBoolean("is_vip")`，修改返回值为 true
3. 隐私审计：看 App 是否偷偷读取通讯录/短信
4. 调试优化：堆栈打印太多时，注释掉 showJavaStacks()

速记：
1. SP 写入 → putXxx，读取 → getXxx
2. ContentResolver → 看到 `content://` 开头的 URI
3. Token 泄露最常见的地方就是 SharedPreferences
*/
