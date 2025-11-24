// Monitor URL operations
// 监控 URL 请求
// java.net.URL: 标准Java URL类。
// 用途：表示统一资源定位符。
// 逆向价值：**高**。尽管现代App多用OkHttp/Retrofit，但底层或某些SDK仍可能使用URL。Hook构造函数可以发现API端点。
function hook_monitor_URL() {
    Java.perform(function () {
        // Hook java.net.URL
        let java_net_URL = Java.use('java.net.URL');
        java_net_URL["$init"].overload('java.lang.String').implementation = function (a) {
            console.log(`[->] java_net_URL.$init is called! args are as follows:\n    ->a= ${a}`);
            var retval = this["$init"](a);
            console.log(`[<-] java_net_URL.$init ended!`);
            return retval;
        };
    });
    console.warn(`[*] hook_monitor_URL is injected!`);
};
hook_monitor_URL();
