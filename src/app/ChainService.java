package com.shancha.ownctl;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.IBinder;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;

import moe.shizuku.server.IRemoteProcess;
import moe.shizuku.server.IShizukuService;
import rikka.shizuku.Shizuku;
import rikka.shizuku.ShizukuBinderWrapper;

/** 开机自启：等 Shizuku 就绪后立刻跑链路，抢开机窗口。 */
public class ChainService extends Service {

    private static final String CH = "ownctl";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(1, note("链路准备中 · 等待 Shizuku"));
        new Thread(new Runnable() {
            public void run() {
                try {
                    waitSystemReady();
                    // 等 binder（最多 25 秒）
                    for (int i = 0; i < 50; i++) {
                        if (Shizuku.pingBinder()) break;
                        try { rikka.shizuku.ShizukuProvider
                                .requestBinderForNonProviderProcess(ChainService.this); } catch (Throwable ignored) { }
                        Thread.sleep(500);
                    }
                    if (!Shizuku.pingBinder()
                            || Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                        upd("Shizuku 未就绪，未执行");
                        stopSelf();
                        return;
                    }
                    String rel = Payloads.uname();
                    String[] pick = Payloads.pick(rel);
                    File bin = new File(getApplicationInfo().nativeLibraryDir,
                            pick[0].equals("own127") ? "libown128.so" : "libown128p.so");
                    File ko = new File(getFilesDir(), "kernelsu_patched.ko");
                    // 服务里必须自己把 ko 从 assets 解出来（MainActivity 做过，服务没做）
                    if (!ko.exists() || ko.length() == 0) {
                        java.io.InputStream in = getAssets().open("kernelsu_patched.ko");
                        java.io.FileOutputStream fo = new java.io.FileOutputStream(ko);
                        byte[] buf = new byte[65536];
                        int n;
                        while ((n = in.read(buf)) > 0) fo.write(buf, 0, n);
                        fo.close(); in.close();
                        upd("已释放模块镜像 " + ko.length() + " 字节");
                    }
                    IShizukuService svc0 = IShizukuService.Stub.asInterface(
                            new ShizukuBinderWrapper(Shizuku.getBinder()));
                    IShizukuService pre = IShizukuService.Stub.asInterface(
                            new ShizukuBinderWrapper(Shizuku.getBinder()));
                    try {
                        pre.newProcess(new String[]{"sh", "-c",
                                "mkdir -p /data/local/tmp/chan; chmod 777 /data/local/tmp/chan;" +
                                " rm -f /data/local/tmp/.lock2 /data/local/tmp/ksu_slide.txt"}, null, "/")
                                .waitFor();
                        upd("预热完成 · 通道就绪");
                    } catch (Throwable ignored) { }
                    /* 用 Payloads.pick() 选出来的那一支灌进去，不能写死 own127：
                       7879 老内核必须用 own127_prev，3666 新内核必须用 own127。 */
                    String sel = pick[0];
                    if (!sameRemote(svc0, "/data/local/tmp/own127", sel)) {
                        pushFile(svc0, sel, "/data/local/tmp/own127", "755");
                    } else {
                        upd("链路已就位 · " + sel + "（跳过灌注）");
                    }
                    if (!sameRemote(svc0, "/data/local/tmp/kernelsu_patched.ko", "kernelsu_patched.ko"))
                        pushFile(svc0, "kernelsu_patched.ko", "/data/local/tmp/kernelsu_patched.ko", "644");
                    /* 与手工可用形态逐字一致（不加 2>&1 / 前置命令 / 不同 cwd）。 */
                    String cmd = "cd /data/local/tmp && rm -rf chan && mkdir -p chan"
                            + " && chmod 777 chan && rm -f .lock2 ksu_slide.txt"
                            + " && ./own127 fake nofix";
                    IShizukuService svc = IShizukuService.Stub.asInterface(
                            new ShizukuBinderWrapper(Shizuku.getBinder()));
                    upd("链路运行中 · " + pick[0]);
                    IRemoteProcess rp = svc.newProcess(new String[]{"sh", "-c", cmd}, null, "/data/local/tmp");
                    InputStream is = new android.os.ParcelFileDescriptor.AutoCloseInputStream(rp.getInputStream());
                    BufferedReader r = new BufferedReader(new InputStreamReader(is));
                    String line;
                    int marks = 0;
                    while ((line = r.readLine()) != null) {
                        if (line.contains("[al] init_module") || line.contains("MODULE LOADED")) break;
                        if (++marks % 40 == 0) upd("链路运行中 · 已读 " + marks + " 行");
                    }
                    waitFor(rp, 180000);
                    boolean ok = moduleLive();
                    if (ok) getSharedPreferences("ownctl", MODE_PRIVATE).edit()
                            .putBoolean("ever_ok", true).apply();
                    upd(ok ? "✔ 模块在线，正在打开 KernelSU" : "本轮未成功，准备重试");
                    if (ok) {
                        openKsu();
                        getSharedPreferences("ownctl", MODE_PRIVATE).edit()
                                .putInt("attempt", 0).apply();
                    } else {
                        int att = getSharedPreferences("ownctl", MODE_PRIVATE)
                                .getInt("attempt", 0) + 1;
                        getSharedPreferences("ownctl", MODE_PRIVATE).edit()
                                .putInt("attempt", att).apply();
                        boolean auto = getSharedPreferences("ownctl", MODE_PRIVATE)
                                .getBoolean("auto_retry", true);
                        long upMs = uptimeMs();
                        if (auto && att <= 3 && upMs > 0 && upMs < 120000) {
                            rebooting("第 " + att + " 轮未成，自动重启再试");
                        } else {
                            upd("本轮未成 · 请手动重启后再试（已停止自动重试）");
                        }
                    }
                } catch (Throwable t) {
                    upd("异常：" + t);
                }
                stopSelf();
            }
        }).start();
        return START_NOT_STICKY;
    }


    /** 等到系统真正可用：boot_completed + 开机动画结束（不看 uptime）。 */
    private void waitSystemReady() {
        // 只等 boot_completed；bootanim 属性在本机型可能一直是空，
        // 不能死等它，否则白等一分钟把窗口耗掉。
        for (int i = 0; i < 120; i++) {
            if ("1".equals(prop("sys.boot_completed"))) break;
            try { Thread.sleep(200); } catch (InterruptedException ignored) { }
        }

    }

    private String prop(String name) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/system/bin/getprop", name});
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            String v = r.readLine();
            p.waitFor();
            return v == null ? "" : v.trim();
        } catch (Throwable t) { return ""; }
    }

private long uptimeMs() {
        try {
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.FileReader("/proc/uptime"));
            String v = r.readLine();
            r.close();
            return (long) (Double.parseDouble(v.split(" ")[0]) * 1000);
        } catch (Throwable t) { return -1; }
    }

    /** 任何外部进程都带超时，避免服务永久挂住。 */
    private int waitFor(IRemoteProcess p, long ms) {
        long end = System.currentTimeMillis() + ms;
        try {
            while (System.currentTimeMillis() < end) {
                try {
                    int v = p.exitValue();
                    return v;
                } catch (Throwable running) { }
                Thread.sleep(120);
            }
            p.destroy();
        } catch (Throwable ignored) { }
        return -1;
    }

    /** 先直接看 /proc/modules，读不到再退 Shizuku。 */
    private boolean moduleLive() {
        try {
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.FileReader("/proc/modules"));
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("kernelsu")) { r.close(); return true; }
            }
            r.close();
            return false;
        } catch (Throwable ignored) { }
        try {
            if (!Shizuku.pingBinder()) return false;
            IShizukuService s2 = IShizukuService.Stub.asInterface(
                    new ShizukuBinderWrapper(Shizuku.getBinder()));
            IRemoteProcess p2 = s2.newProcess(new String[]{"sh", "-c",
                    "grep -c kernelsu /proc/modules"}, null, "/");
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(
                    new android.os.ParcelFileDescriptor.AutoCloseInputStream(p2.getInputStream())));
            String v = r.readLine();
            waitFor(p2, 5000);
            return v != null && !v.trim().isEmpty() && !v.trim().equals("0");
        } catch (Throwable t) { return false; }
    }

    private void openKsu() {
        try {
            android.content.Intent i = getPackageManager()
                    .getLaunchIntentForPackage("me.weishu.kernelsu");
            if (i != null) {
                i.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(i);
            }
        } catch (Throwable ignored) { }
    }

    private void rebooting(String why) {
        upd(why);
        try {
            if (!Shizuku.pingBinder()) return;
            IShizukuService s2 = IShizukuService.Stub.asInterface(
                    new ShizukuBinderWrapper(Shizuku.getBinder()));
            IRemoteProcess p2 = s2.newProcess(new String[]{"sh", "-c",
                    "svc power reboot || reboot"}, null, "/");
            waitFor(p2, 30000);
        } catch (Throwable ignored) { }
    }


    /** 远端文件是否与 assets 里那份逐字节一致（md5）。 */
    private boolean sameRemote(IShizukuService s2, String path, String asset) {
        String want = assetMd5(asset);
        if (want == null || want.isEmpty()) return false;
        return want.equalsIgnoreCase(remoteMd5(s2, path));
    }

    private String assetMd5(String asset) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            java.io.InputStream in = getAssets().open(asset);
            byte[] b = new byte[65536];
            int n;
            while ((n = in.read(b)) > 0) md.update(b, 0, n);
            in.close();
            return hex(md.digest());
        } catch (Throwable t) { return null; }
    }

    private String remoteMd5(IShizukuService s2, String path) {
        try {
            IRemoteProcess p = s2.newProcess(new String[]{"sh", "-c",
                    "md5sum " + path + " 2>/dev/null || echo"}, null, "/");
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(
                    new android.os.ParcelFileDescriptor.AutoCloseInputStream(p.getInputStream())));
            String v = r.readLine();
            p.waitFor();
            if (v == null) return "";
            String[] f = v.trim().split("\\s+");
            return f.length > 0 ? f[0] : "";
        } catch (Throwable t) { return ""; }
    }

    private static String hex(byte[] d) {
        StringBuilder sb = new StringBuilder(d.length * 2);
        for (byte x : d) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /** 用 Shizuku 的进程 stdin 把 assets 灌进 /data/local/tmp（shell 读不到 app 私有目录）。 */
    private String remoteSize(IShizukuService s2, String path) {
        try {
            IRemoteProcess p = s2.newProcess(new String[]{"sh", "-c",
                    "stat -c %s " + path + " 2>/dev/null || echo"}, null, "/");
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(
                    new android.os.ParcelFileDescriptor.AutoCloseInputStream(p.getInputStream())));
            String v = r.readLine();
            p.waitFor();
            return v == null ? "" : v.trim();
        } catch (Throwable t) { return ""; }
    }

    private void pushFile(IShizukuService svc, String asset, String dest, String mode)
            throws Exception {
        IRemoteProcess p = svc.newProcess(
                new String[]{"sh", "-c", "rm -f " + dest + "; cat > " + dest}, null, "/");
        java.io.OutputStream os = new android.os.ParcelFileDescriptor.AutoCloseOutputStream(
                p.getOutputStream());
        java.io.InputStream in = getAssets().open(asset);
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) os.write(buf, 0, n);
        os.close(); in.close();
        waitFor(p, 30000);
        IRemoteProcess c = svc.newProcess(
                new String[]{"sh", "-c", "chmod " + mode + " " + dest + "; ls -l " + dest}, null, "/");
        java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(
                new android.os.ParcelFileDescriptor.AutoCloseInputStream(c.getInputStream())));
        String line = r.readLine();
        c.waitFor();
        upd("灌入 " + asset + " → " + (line == null ? "?" : line.trim()));
    }

    private Notification note(String text) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            NotificationChannel c = new NotificationChannel(CH, "链路", NotificationManager.IMPORTANCE_LOW);
            nm.createNotificationChannel(c);
        }
        return new Notification.Builder(this, CH)
                .setContentTitle("山茶 · 内核工坊")
                .setContentText(text)
                .setSmallIcon(R.mipmap.ic_launcher)
                .build();
    }

    private void upd(String t) {
        try { getSystemService(NotificationManager.class).notify(1, note(t)); } catch (Throwable ignored) { }
    }

    @Override
    public IBinder onBind(Intent i) { return null; }
}
