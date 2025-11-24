package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 8: Bypass Check (绕过检测)
 * Scripts for bypassing various security checks and detections
 */
public class BypassCheck {
    
    private static final String BASE_PATH = "frida-scripts/08-bypass-check/";
    
    // 第8类目前为空，你可以在这里添加各种绕过检测的脚本
    public static final ScriptEntry BYPASS_MSA = new ScriptEntry(
        "Bypass MSA",
        "绕过MSA检测",
        ScriptLoader.loadScript(BASE_PATH + "01-bypass-msa.js")
    );
}
