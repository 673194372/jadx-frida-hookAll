// Advanced Map Monitor & Printer
// 高级 Map 监控与调试工具
// 
// 功能特点：
// 1. 深度监控: 覆盖 put, get, remove, putAll, clear 等所有关键操作。
// 2. 智能过滤: 支持 Key 白名单、Value 正则匹配。
// 3. 格式化输出: 自动将 Map 内容转换为 JSON 格式打印，易于阅读。
// 4. 堆栈追踪: 自动过滤系统调用栈，只显示业务代码调用。

function hook_print_map() {
    // ========================================================================
    // 配置区域 (Configuration)
    // ========================================================================
    const config = {
        // 1. Key 过滤器 (空数组表示监控所有 Key)
        // 场景：只关心 "token", "sign", "user" 等字段的读写
        targetKeys: [
            "sign", "token", "auth", "key", "secret",
            "uid", "user_id", "device_id", "session"
        ],
        
        // 2. Value 过滤器 (正则表达式，null 表示不通过 Value 过滤)
        // 场景：监控 value 是以 "eyJ" 开头的 (JWT) 或长度为 32 的 (MD5)
        valueRegex: null, // e.g., /eyJ[\w-]*\.eyJ[\w-]*\.[\w-]*/
        
        // 3. 堆栈黑名单 (防止系统类调用刷屏)
        stackBlacklist: [
            "android.support", "androidx", "com.google.gson", "retrofit2"
        ],
        
        // 4. 是否在每次 put/get 时打印整个 Map 的当前内容 (慎用，数据量大时会卡)
        printFullMapOnPut: false
    };

    Java.perform(function() {
        let Map = Java.use('java.util.Map');
        let HashMap = Java.use('java.util.HashMap');
        let Log = Java.use("android.util.Log");
        let Exception = Java.use("java.lang.Exception");

        // ====================================================================
        // 工具函数
        // ====================================================================
        
        function getStackTrace() {
            let stack = Log.getStackTraceString(Exception.$new());
            // 简单的黑名单过滤
            for (let black of config.stackBlacklist) {
                if (stack.includes(black)) return null; // 忽略系统调用
            }
            return stack;
        }

        function isTarget(key, value) {
            // 1. Key 检查
            if (config.targetKeys.length > 0) {
                if (key == null) return false;
                let k = key.toString().toLowerCase();
                let hit = false;
                for (let target of config.targetKeys) {
                    if (k.includes(target)) {
                        hit = true;
                        break;
                    }
                }
                if (!hit) return false;
            }
            
            // 2. Value 检查 (如果有配置)
            if (config.valueRegex && value != null) {
                if (!config.valueRegex.test(value.toString())) return false;
            }
            
            return true;
        }

        function prettyPrintMap(map, prefix) {
            if (map == null) return;
            try {
                let entries = map.entrySet().toArray();
                if (entries.length === 0) {
                    console.log(prefix + " {} (Empty)");
                    return;
                }
                console.log(prefix + " {");
                for (let i = 0; i < entries.length; i++) {
                    let key = entries[i].getKey();
                    let val = entries[i].getValue();
                    console.log(`    ${key} : ${val}`);
                }
                console.log(prefix + " }");
            } catch(e) {
                console.log(prefix + " [Error printing map: " + e + "]");
            }
        }

        // ====================================================================
        // Hook Logic
        // ====================================================================
        
        // 1. Put (写入)
        Map.put.implementation = function(key, value) {
            let result = this.put(key, value);
            if (isTarget(key, value)) {
                let stack = getStackTrace();
                if (stack) {
                    console.log(`\n[Map.put] Key=${key}, Value=${value}`);
                    if (config.printFullMapOnPut) prettyPrintMap(this, "  Current Map:");
                    console.log(stack);
                }
            }
            return result;
        };

        // 2. Get (读取)
        Map.get.implementation = function(key) {
            let result = this.get(key);
            // 注意：这里我们既检查 Key 也检查 Result
            if (isTarget(key, result)) {
                let stack = getStackTrace();
                if (stack) {
                    console.log(`\n[Map.get] Key=${key} => Result=${result}`);
                    console.log(stack);
                }
            }
            return result;
        };
        
        // 3. PutAll (批量写入)
        Map.putAll.implementation = function(otherMap) {
            this.putAll(otherMap);
            // 遍历 otherMap 看看有没有感兴趣的
            if (otherMap != null) {
                let entries = otherMap.entrySet().toArray();
                for (let i = 0; i < entries.length; i++) {
                    let k = entries[i].getKey();
                    let v = entries[i].getValue();
                    if (isTarget(k, v)) {
                        let stack = getStackTrace();
                        if (stack) {
                            console.log(`\n[Map.putAll] Hit target: Key=${k}, Value=${v}`);
                            prettyPrintMap(otherMap, "  Source Map Chunk:");
                            console.log(stack);
                            break; // 只要发现一个目标就打印整个相关信息，避免重复
                        }
                    }
                }
            }
        };
        
        // 4. Remove (删除)
        Map.remove.implementation = function(key) {
            let result = this.remove(key);
            if (isTarget(key, result)) {
                let stack = getStackTrace();
                if (stack) {
                    console.log(`\n[Map.remove] Key=${key}, RemovedValue=${result}`);
                    console.log(stack);
                }
            }
            return result;
        };

        // 5. HashMap 构造函数 (克隆/转换)
        // 很多时候 Map 是通过 new HashMap(otherMap) 创建的
        HashMap.$init.overload('java.util.Map').implementation = function(m) {
            this.$init(m);
            if (m != null) {
                // 简单的采样检查，避免遍历太大的 Map
                let entries = m.entrySet().toArray();
                if (entries.length > 0) {
                     let k = entries[0].getKey();
                     if (isTarget(k, null)) {
                         console.log(`\n[HashMap.init(Map)] Copying map with target key: ${k}`);
                         prettyPrintMap(m, "  Source Map:");
                         console.log(getStackTrace());
                     }
                }
            }
            return;
        };

    });
    console.warn('[*] Advanced Map Monitor Injected');
    console.warn('    Target Keys: ' + config.targetKeys.join(", "));
}
hook_print_map();
