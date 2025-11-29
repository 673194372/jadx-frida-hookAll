package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 6: Hook JNI (JNI相关)
 * Scripts for hooking JNI functions and native methods
 */
public class HookJNI {
    
    private static final String BASE_PATH = "frida-scripts/06-hook-jni/";
    
    /**
     * Hook RegisterNatives - 监控所有 JNI 函数注册
     * 逆向价值极高：快速定位所有 Native 函数的地址和签名
     */
    public static final ScriptEntry HOOK_REGISTER_NATIVES = new ScriptEntry(
        "Hook RegisterNatives",
        "监控JNI函数注册",
        ScriptLoader.loadScript(BASE_PATH + "01-hook-register-natives.js")
    );
    
    /**
     * JNITrace Usage - jnitrace工具的使用说明
     * jnitrace是基于Frida的JNI函数追踪工具，自动解析参数
     */
    public static final ScriptEntry JNITRACE_USAGE = new ScriptEntry(
        "JNITrace Usage Guide",
        "JNITrace工具使用说明",
        ScriptLoader.loadScript(BASE_PATH + "02-jnitrace-usage.js")
    );
}
