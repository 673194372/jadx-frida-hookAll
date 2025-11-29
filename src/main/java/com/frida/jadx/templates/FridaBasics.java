package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 1: Frida APIs (Frida API)
 * Common Frida API usage and hooking examples
 */
public class FridaBasics {
    
    private static final String BASE_PATH = "frida-scripts/01-frida-apis/";
    
    public static final ScriptEntry HOOK_BASIC = new ScriptEntry(
        "Hook Basic Method",
        "Hook普通方法",
        ScriptLoader.loadScript(BASE_PATH + "01-hook-basicHook.js")
    );
    
    public static final ScriptEntry HOOK_OVERLOAD = new ScriptEntry(
        "Hook Overloaded Method",
        "Hook重载方法",
        ScriptLoader.loadScript(BASE_PATH + "02-hook-overload.js")
    );
    
    public static final ScriptEntry HOOK_CONSTRUCTOR = new ScriptEntry(
        "Hook Constructor",
        "Hook构造函数",
        ScriptLoader.loadScript(BASE_PATH + "04-hook-classConstructor.js")
    );
    
    public static final ScriptEntry HOOK_FIELD = new ScriptEntry(
        "Hook Field",
        "Hook字段",
        ScriptLoader.loadScript(BASE_PATH + "03-hook-field.js")
    );
    
    public static final ScriptEntry HOOK_INNER_CLASS = new ScriptEntry(
        "Hook Inner Class",
        "Hook内部类",
        ScriptLoader.loadScript(BASE_PATH + "05-hook-inner-class.js")
    );
    
    public static final ScriptEntry ENUMERATE_CLASSES = new ScriptEntry(
        "Enumerate Classes",
        "枚举类和方法",
        ScriptLoader.loadScript(BASE_PATH + "06-enumerate-classes.js")
    );
    
    public static final ScriptEntry RPC_CALL_METHOD = new ScriptEntry(
        "RPC Call Method",
        "主动调用方法(RPC)",
        ScriptLoader.loadScript(BASE_PATH + "07-rpc-call-method.js")
    );
}
