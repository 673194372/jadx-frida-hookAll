// 统计全局dump了几个so，防止同名的so被复写
var dump_num = 1;
function dump_so(so_name) {
    Java.perform(function () {
        console.warn(`[*] ========== Dumping ${so_name} ... ========== `);
        var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
        var dir = currentApplication.getApplicationContext().getFilesDir().getPath();
        var libso = Process.getModuleByName(so_name);
        console.log("[name]:", libso.name);
        console.log("[base]:", libso.base);
        console.log("[size]:", ptr(libso.size));
        console.log("[path]:", libso.path);
        var file_path = dir + "/" + libso.name + "_" + libso.base + "_" + ptr(libso.size) + "_" + dump_num + ".so";
        var file_handle = new File(file_path, "wb");
        if (file_handle && file_handle != null) {
            Memory.protect(ptr(libso.base), libso.size, "rwx");
            var libso_buffer = ptr(libso.base).readByteArray(libso.size);
            file_handle.write(libso_buffer);
            file_handle.flush();
            file_handle.close();
            console.log("[dump]:", file_path);
        }
        dump_num++;
        console.warn(`[*] ========== Dump ${so_name} completely ========== `);
    });
    console.warn("[*] dump_so is injected!");
}

// dump_so("libxyass.so")
// adb shell
// su
// cp <路径> /sdcard/libs/

// adb pull /sdcard/libs/
// 然后根据位数使用SoFixer进行修复
// .\64SoFixer-Windows.exe -m <基地址> -s <待修复so文件路径> -o <修复后so文件路径>