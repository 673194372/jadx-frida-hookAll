package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 7: Frida Advanced (Frida进阶)
 * Advanced Frida features and utilities
 */
public class FridaAdvanced {
    
    private static final String BASE_PATH = "frida-scripts/07-frida-advancedApi/";
    
    public static final ScriptEntry CALL_METHODS = new ScriptEntry(
        "Call Methods Actively",
        "主动调用方法",
        ScriptLoader.loadScript(BASE_PATH + "01-call-methods.js")
    );
    
    public static final ScriptEntry CLASSLOADER_HELPER = new ScriptEntry(
        "ClassLoader Helper",
        "ClassLoader辅助",
        ScriptLoader.loadScript(BASE_PATH + "02-classloader-helper.js")
    );
    
    public static final ScriptEntry DUMP_CERTIFICATE = new ScriptEntry(
        "Dump Certificate",
        "Dump证书",
        ScriptLoader.loadScript(BASE_PATH + "03-dump-certificate.js")
    );
    
    public static final ScriptEntry LOAD_DEX = new ScriptEntry(
        "Load DEX Dynamically",
        "动态加载DEX",
        ScriptLoader.loadScript(BASE_PATH + "04-load-dex.js")
    );
    
    public static final ScriptEntry JNI_REGISTER_NATIVES = new ScriptEntry(
        "JNI RegisterNatives",
        "监控JNI注册",
        ScriptLoader.loadScript(BASE_PATH + "05-jni-register-natives.js")
    );
}
