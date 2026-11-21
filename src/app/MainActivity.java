package com.shancha.ownctl;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.graphics.Typeface;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewParent;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import moe.shizuku.server.IRemoteProcess;
import moe.shizuku.server.IShizukuService;
import rikka.shizuku.Shizuku;
import rikka.shizuku.ShizukuBinderWrapper;
import rikka.shizuku.ShizukuProvider;
import android.os.IBinder;

/**
 * 山茶 · 内核工坊 —— 手机端 own128 链路。
 *
 * 执行身份：Shizuku（无线调试授权后常驻的 shell 服务）。
 * 阶段：①自检 ②标定 ③定位 ④回收 ⑤落位 ⑥装载。
 */
public class MainActivity extends Activity implements Shizuku.OnRequestPermissionResultListener {

    private static final String[][] STAGE = {
            {"[check]", "①自检"},
            {"[base]", "②标定"},
            {"direct map base", "②标定"},
            {"[cred]", "③定位"},
            {"plant1 V=", "④回收"},
            {"slab_own", "④回收"},
            {"fake cred A=", "⑤落位"},
            {"[fix]", "⑤落位"},
            {"[kw]", "⑥装载"},
            {"[al]", "⑥装载"},
            {"init_module rc", "⑥装载"},
            {"MODULE LOADED", "完成"},
            {"kernelsu ", "完成"},
    };
    private int C_TIME = 0xFF93A3B4, C_STAGE = 0xFF17A673, C_MSG = 0xFF3D4F63;
    private int C_OK = 0xFF12A06B, C_BAD = 0xFFD8623A, C_DIM = 0xFFAEBAC7;
    /** 进度这类强调文字：两套主题都用品牌绿，避免切换后被普通副色顶掉。 */
    private int accent = 0xFF12A06B;
    

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final StringBuilder raw = new StringBuilder();
    private final java.util.ArrayList<String> hist = new java.util.ArrayList<String>();
    /** 与 hist 一一对应的行类型（1=成功），重绘时颜色才不会漂。 */
    private final java.util.ArrayList<Integer> histKind = new java.util.ArrayList<Integer>();
    /** 与 hist 一一对应的原始时间戳，重绘后仍显示当初的时间。 */
    private final java.util.ArrayList<Long> histTime = new java.util.ArrayList<Long>();
    /** 视图里最多重放多少行：既够看，又不会把 TextView 撑到黑块。 */
    private static final int LOG_MAX_LINES = 300;

    /**
     * 主题切换后用新配色重绘已有日志。
     * 只重绘、不再记账：旧实现走 narrate()->emit()，会在遍历 hist 的同一循环里
     * 往 hist 追加元素（i < hist.size() 永远成立），一次换肤就能灌进上千行重复日志。
     */
    private void rebuildLog() {
        if (log == null) return;
        try {
            java.util.ArrayList<String> snap;
            java.util.ArrayList<Integer> kinds;
            java.util.ArrayList<Long> times;
            synchronized (hist) {
                snap = new java.util.ArrayList<String>(hist);
                kinds = new java.util.ArrayList<Integer>(histKind);
                times = new java.util.ArrayList<Long>(histTime);
            }
            log.setText("");
            lineCount = 0;
            raw.setLength(0);
            int from = Math.max(0, snap.size() - LOG_MAX_LINES);
            for (int i = from; i < snap.size(); i++) {
                String line = snap.get(i);
                renderLine(line, kinds.get(i).intValue(), times.get(i).longValue());
                raw.append(line).append('\n');
                lineCount++;
            }
            /* 重绘后回到最新一行，和实时追加时的位置一致 */
            if (scroll != null) scroll.post(new Runnable() {
                public void run() {
                    try { scroll.fullScroll(View.FOCUS_DOWN); } catch (Throwable ignored) { }
                }
            });
        } catch (Throwable ignored) { }
    }
    private final SimpleDateFormat ts = new SimpleDateFormat("HH:mm:ss", Locale.US);
    private final View[] pills = new View[6];

    private TextView log, stage, hint, progress, badge;
    private ScrollView scroll;
    /** 日志是否跟随最新一行：只有用户自己往上翻历史时才停。 */
    private boolean followLog = true;
    /** 已排队的滚动任务，合并同一帧内的多次追加。 */
    private boolean scrollPending = false;
    private volatile boolean running;
    private int stageIdx = 0;
    private ObjectAnimator breathe;
    private IShizukuService svc;
    private IRemoteProcess rp;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        try { onCreateSafe(b); } catch (Throwable t) {
            try {
                android.widget.TextView tv = new android.widget.TextView(this);
                tv.setText("界面加载失败：" + t + "\n" + android.util.Log.getStackTraceString(t));
                tv.setTextColor(0xFFCC0000);
                tv.setPadding(40, 200, 40, 40);
                setContentView(tv);
            } catch (Throwable ignored) { }
        }
    }

    private void onCreateSafe(Bundle b) {
        immersive();
        setContentView(R.layout.activity_main);

        applyInsets(findViewById(R.id.root));

        // 先把所有视图绑定出来，再套主题：旧顺序里 applyTheme() 跑在 log 赋值之前，
        // 冷启动那一次换肤其实没生效，日志底色/字色会和切过主题后不一致。
        log = findViewById(R.id.log);
        scroll = findViewById(R.id.scroll);
        stage = findViewById(R.id.stage);
        hint = findViewById(R.id.stageHint);
        progress = findViewById(R.id.progressText);
        badge = findViewById(R.id.badge);
        pills[0] = findViewById(R.id.p1);
        pills[1] = findViewById(R.id.p2);
        pills[2] = findViewById(R.id.p3);
        pills[3] = findViewById(R.id.p4);
        pills[4] = findViewById(R.id.p5);
        pills[5] = findViewById(R.id.p6);
        installLogScroll();

        try {
            pressFx(findViewById(R.id.start));
            bindVersionPicker();
        recoverLastRun();
        findViewById(R.id.logSave).setOnClickListener(new android.view.View.OnClickListener() {
            public void onClick(android.view.View v) { bounce(v); exportLog(); }
        });
        findViewById(R.id.logSave).setOnLongClickListener(new android.view.View.OnLongClickListener() {
            public boolean onLongClick(android.view.View v) { bounce(v); exportDiag(); return true; }
        });
        findViewById(R.id.copy).setOnLongClickListener(new android.view.View.OnLongClickListener() {
            public boolean onLongClick(android.view.View v) {
                bounce(v);
                exportLog();
                return true;
            }
        });
        pressFx(findViewById(R.id.stop));
            pressFx(findViewById(R.id.copy));
        } catch (Throwable ignored) { }
        try {
            final View th = findViewById(R.id.theme);
            if (th != null) th.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    bounce(v);
                    darkUI = !darkUI;     /* 只在本次运行内切换，重启回到默认浅色 */
                    applyTheme();
                    /* 图标转半圈，切换有交代 */
                    th.animate().rotationBy(180f).setDuration(320)
                            .setInterpolator(new DecelerateInterpolator(1.4f)).start();
                    emit(darkUI ? "已切换到深色模式" : "已切换到浅色模式", 0);
                }
            });
        } catch (Throwable ignored) { }
        applyTheme();
        installGlass();
        try {
            View sc = findViewById(R.id.statusCard);
            if (sc != null) {
                android.animation.ObjectAnimator oa = android.animation.ObjectAnimator.ofFloat(
                        sc, "translationY", 0f, -6f, 0f);
                oa.setDuration(3200);
                oa.setRepeatCount(android.animation.ValueAnimator.INFINITE);
                oa.setInterpolator(new android.view.animation.AccelerateDecelerateInterpolator());
                oa.start();
            }
        } catch (Throwable ignored) { }
        enterAnimation();
        findViewById(R.id.start).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { bounce(v); safeCall(new Runnable() { public void run() { start(); } }); }
        });
        findViewById(R.id.stop).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                bounce(v);
                /* P1-9：成功后 / 已接管 / 已驻留一律拒绝中止（杀驻留进程会放掉持有的页）。
                   命中缓存先拒绝，没命中再后台复核一次，不在主线程做阻塞 IPC。 */
                if (successDeclared || sawSuccess || parkedZombie || stateTaken) {
                    emit("已接管/已驻留 · 中止会释放持有的页并可能触发内核崩溃，已拒绝", 0);
                    return;
                }
                new Thread(new Runnable() {
                    public void run() {
                        boolean mod = false;
                        try { mod = moduleLoaded(); } catch (Throwable ignored) { }
                        if (mod) {
                            stateTaken = true;
                            startLocked = true;
                            ui.post(new Runnable() { public void run() {
                                try { applyUiTaken("模块 kernelsu 在线 · 中止已拒绝"); } catch (Throwable ignored) { }
                                emit("已接管内核 · 中止会释放持有的页并可能触发内核崩溃，已拒绝", 0);
                            }});
                            return;
                        }
                        try {
                            if (Shizuku.pingBinder()
                                    && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                                svcRef = IShizukuService.Stub.asInterface(
                                        new ShizukuBinderWrapper(Shizuku.getBinder()));
                                /* 按 PID 清理，不用 pkill -f（会自匹配到本命令的 sh -c） */
                                killChainIfSafe();
                            }
                        } catch (Throwable t) {
                            emit("中止失败：" + t.getClass().getSimpleName(), 0);
                        }
                        ui.post(new Runnable() { public void run() { stop(); } });
                    }
                }).start();
            }
        });
        findViewById(R.id.copy).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                bounce(v);
                try {
                    ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                    cm.setPrimaryClip(ClipData.newPlainText("own128", raw.toString()));
                    emit("日志已复制（" + raw.length() + " 字符）", 1);
                } catch (Throwable t) { emit("复制失败：" + t.getClass().getSimpleName(), 0); }
            }
        });
        findViewById(R.id.reboot).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { bounce(v); safeCall(new Runnable() { public void run() { reboot(); } }); }
        });

        installCrashGuard();
        /* P0-1：冷启动就把真实运行态回填进界面（异步，不阻塞主线程） */
        refreshRealState();
        /* 自检通道：外部可 `am start --ez probe_fgs true` 验证前台服务 type 合法，
           只拉起 ChainService 的 probe 分支，绝不执行载荷链路。 */
        try {
            if (getIntent() != null && getIntent().getBooleanExtra("probe_fgs", false)) {
                getIntent().removeExtra("probe_fgs");
                android.content.Intent si = new android.content.Intent(this, ChainService.class);
                si.putExtra("probe", true);
                if (android.os.Build.VERSION.SDK_INT >= 26) startForegroundService(si);
                else startService(si);
                emit("· 自检 · 已拉起前台服务 probe 分支（不执行载荷）", 0);
            }
        } catch (Throwable ignored) { }
        try {
            if (getIntent() != null && getIntent().getBooleanExtra("probe_log", false)) {
                getIntent().removeExtra("probe_log");
                emit("· 自检 · 开始日志链路自检（不执行载荷）", 0);
                selfTestLog();
            }
        } catch (Throwable ignored) { }
        if (android.os.Build.VERSION.SDK_INT >= 33
                && checkSelfPermission("android.permission.POST_NOTIFICATIONS")
                   != PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 2001);
        Shizuku.addBinderDeadListener(new Shizuku.OnBinderDeadListener() {
            public void onBinderDead() { emit("Shizuku 连接断开 · 请重新拉起 Shizuku", 0); }
        });
        Shizuku.addRequestPermissionResultListener(this);
        // binder 是异步送达的：粘性监听，到了就立刻申请授权
        Shizuku.addBinderReceivedListenerSticky(new Shizuku.OnBinderReceivedListener() {
            public void onBinderReceived() { sayShizukuState(); }
        });
        // 非 provider 进程要先主动向 Shizuku 取 binder，否则 pingBinder 永远为 false
        try {
            ShizukuProvider.requestBinderForNonProviderProcess(this);
        } catch (Throwable ignored) { }
        emit("工坊就绪 · 内核 " + Payloads.uname(), 0);
        sayShizukuState();
        ui.postDelayed(new Runnable() {
            public void run() { sayShizukuState(); }
        }, 800);
    }

    @Override
    protected void onResume() {
        super.onResume();
        /* P0-1：每次回到前台都按真实状态回填一次（模块/进程都可能在这期间变化） */
        try { refreshRealState(); } catch (Throwable ignored) { }
    }

    @Override
    protected void onDestroy() {
        Shizuku.removeRequestPermissionResultListener(this);
        try { if (breathe != null) breathe.cancel(); } catch (Throwable ignored) { }
        /* 用户直接划掉 App：仍在跑且未成功 → 按失败路径清理，避免留下空占资源的 7879 进程。
           已成功/已驻留/已接管 一律不碰（killChainIfSafe 内部还有一道拒绝）。 */
        try { cleanupOnLeave(); } catch (Throwable ignored) { }
        super.onDestroy();
    }

    @Override
    public void onRequestPermissionResult(int requestCode, int grantResult) {
        if (grantResult == PackageManager.PERMISSION_GRANTED)
            emit("Shizuku 授权成功，可以启动链路", 1);
        else
            emit("Shizuku 授权被拒绝，请在 Shizuku 里手动允许本应用", 0);
        asked = 0;
        sayShizukuState();
    }

    private int asked;
    private int lineCount;


    /** 入场：状态卡、按钮、日志卡依次淡入上浮。 */

    /** 任何未捕获异常只记录，不让界面直接闪退。 */
    private void installCrashGuard() {
        final Thread.UncaughtExceptionHandler prev = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            public void uncaughtException(Thread t, Throwable e) {
                /* 任何未捕获异常都不许让「运行中」这个门闩卡在 true（P0-3） */
                try { running = false; } catch (Throwable ignored) { }
                try {
                    java.io.FileWriter w = new java.io.FileWriter(
                            new java.io.File(getFilesDir(), "last_crash.txt"), false);
                    w.write(new java.util.Date() + " " + t.getName() + "\n");
                    java.io.StringWriter sw = new java.io.StringWriter();
                    e.printStackTrace(new java.io.PrintWriter(sw));
                    w.write(sw.toString());
                    w.close();
                } catch (Throwable ignored) { }
                try {
                    ui.post(new Runnable() { public void run() {
                        try { emit("已拦截一次异常，界面继续可用", 0); } catch (Throwable ignored) { }
                    }});
                } catch (Throwable ignored) { }
            }
        });
        try {
            java.io.File f = new java.io.File(getFilesDir(), "last_crash.txt");
            if (f.exists() && f.length() > 0)
                emit("上次异常已记录（last_crash.txt）", 0);
        } catch (Throwable ignored) { }
    }

    /** Shizuku 调用一律包一层，binder 死掉时不崩界面。 */
    private boolean safeCall(Runnable r) {
        try { r.run(); return true; }
        catch (Throwable t) { emit("操作失败：" + t.getClass().getSimpleName(), 0); return false; }
    }


    /** 高斯玻璃底：两团模糊光斑缓缓浮动，卡片半透明叠在上面。 */

    /** 默认浅色：每次冷启动都从浅色开始，切换只在本次运行内生效，不落盘。 */
    private boolean darkUI = false;

    private boolean darkMode() {
        return darkUI;
    }

    private void applyTheme() {
        boolean dark = darkMode();
        try {
            int pageBg = dark ? R.drawable.bg_dark : R.drawable.bg_root;
            int cardBg = dark ? R.drawable.card_dark : R.drawable.card;
            int btnBg = dark ? R.drawable.btn_dark : R.drawable.btn;
            int main = dark ? 0xFFFFFFFF : 0xFF16202B;
            int sub = dark ? 0xFFA9BACC : 0xFF6B7A8C;

            /* 先定色板，再递归上色：recolor() 内部要用到 C_MSG / accent */
            if (dark) {
                C_TIME = 0xFF9FB0C4; C_STAGE = 0xFF2FD79B; C_MSG = 0xFFF2F6FA;
                C_OK = 0xFF3DDC97;  C_BAD = 0xFFFF8A65;  C_DIM = 0xFF8FA0B4;
                accent = 0xFF4FE3AC;
            } else {
                C_TIME = 0xFF93A3B4; C_STAGE = 0xFF17A673; C_MSG = 0xFF3D4F63;
                C_OK = 0xFF12A06B;  C_BAD = 0xFFD8623A;  C_DIM = 0xFFAEBAC7;
                accent = 0xFF12A06B;
            }

            getWindow().setBackgroundDrawableResource(pageBg);
            getWindow().getDecorView().setBackgroundResource(pageBg);

            View root = findViewById(R.id.root);
            if (root != null) {
                recolor(root, dark, pageBg, cardBg, btnBg, main, sub);
                View p = (View) root.getParent();
                if (p != null) p.setBackgroundResource(pageBg);
            }
            TextView th = findViewById(R.id.theme);
            if (th != null) {
                th.setBackgroundResource(btnBg);
                th.setTextColor(sub);
                th.setText(dark ? "\u2600" : "\u263E");
            }
            /* 深色底必须配浅色系统栏图标，否则状态栏黑字压在近黑背景上看不见 */
            applySystemBarIcons(dark);

            if (log != null) {
                log.setTextColor(C_MSG);
                log.setBackgroundColor(0x00000000);
                log.setAlpha(1f);
                log.setTranslationY(0f);
                rebuildLog();          /* 只重绘，不再往 hist 里追加 */
            }
            if (scroll != null) scroll.setBackgroundColor(0x00000000);
            refreshPills();
            refreshBadge();
            /* recolor() 会把 start 的字色刷回白色；锁着的时候必须再把灰态盖回去，
               否则白字压在灰胶囊上看不见，就像按钮“被挡住” */
            if (startLocked) lockStartButton("已锁定");
        } catch (Throwable ignored) { }
    }

    /** 状态栏/导航栏图标颜色跟随主题。 */
    private void applySystemBarIcons(boolean dark) {
        try {
            int f = View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                    | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                    | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION;
            if (!dark) f |= View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
                    | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
            getWindow().getDecorView().setSystemUiVisibility(f);
        } catch (Throwable ignored) { }
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            try {
                android.view.WindowInsetsController ic = getWindow().getInsetsController();
                if (ic != null) {
                    int mask = android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                            | android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
                    ic.setSystemBarsAppearance(dark ? 0 : mask, mask);
                }
            } catch (Throwable ignored) { }
        }
    }

    /** 换肤后把六段进度条的已点亮状态还原。 */
    private void refreshPills() {
        boolean dark = darkMode();
        for (int i = 0; i < 6; i++) {
            View p = pills[i];
            if (p == null) continue;
            try {
                p.setBackgroundResource(i < Math.min(stageIdx, 6)
                        ? R.drawable.pill_on
                        : (dark ? R.drawable.pill_dark : R.drawable.pill_off));
            } catch (Throwable ignored) { }
        }
    }

    /** 换肤后把状态徽标还原成当前语义（在线=绿胶囊，其它=按钮底色）。 */
    private void refreshBadge() {
        if (badge == null) return;
        boolean dark = darkMode();
        try {
            if (stageIdx >= 7) {
                badge.setText(stateTaken ? "已接管" : "在线");
                badge.setBackgroundResource(R.drawable.pill_on);
                badge.setTextColor(0xFFFFFFFF);
            } else {
                badge.setBackgroundResource(dark ? R.drawable.pill_dark : R.drawable.pill_off);
                badge.setTextColor(dark ? 0xFFA9BACC : 0xFF7387A0);
            }
        } catch (Throwable ignored) { }
    }

    /** 递归换肤：容器按角色上卡片底，文字按角色换色（主标题 / 副文 / 强调 / 日志）。 */
    private void recolor(View v, boolean dark, int pageBg, int cardBg, int btnBg,
                         int main, int sub) {
        int vid = v.getId();
        if (v instanceof android.view.ViewGroup) {
            if (vid == R.id.statusCard)
                v.setBackgroundResource(cardBg);
            else if (vid == R.id.logCard)
                v.setBackgroundResource(dark ? R.drawable.card_dark2 : R.drawable.card);
            else
                v.setBackgroundColor(0x00000000);   /* 其余容器一律透明，避免色块与黑块 */
            android.view.ViewGroup g = (android.view.ViewGroup) v;
            for (int i2 = 0; i2 < g.getChildCount(); i2++)
                recolor(g.getChildAt(i2), dark, pageBg, cardBg, btnBg, main, sub);
            return;
        }
        if (v instanceof android.widget.ImageView) {
            try {
                android.widget.ImageView iv = (android.widget.ImageView) v;
                iv.setImageResource(dark ? R.drawable.ic_dark : R.drawable.ic_launch_fg);
                /* 头像底盘也要跟着换，否则深色主题下留一圈白边 */
                iv.setBackgroundResource(dark ? R.drawable.card_dark : R.drawable.card);
            } catch (Throwable ignored) { }
            return;
        }
        if (v instanceof TextView) {
            TextView t = (TextView) v;
            if (vid == R.id.start) {
                t.setTextColor(0xFFFFFFFF);
            } else if (vid == R.id.log) {
                t.setTextColor(C_MSG);
                t.setBackgroundColor(0x00000000);
            } else if (vid == R.id.stage) {
                t.setTextColor(main);
            } else if (vid == R.id.progressText) {
                t.setTextColor(accent);
            } else if (vid == R.id.badge) {
                t.setBackgroundResource(dark ? R.drawable.pill_dark : R.drawable.pill_off);
                t.setTextColor(sub);
            } else if (vid == R.id.theme || vid == R.id.stop
                    || vid == R.id.copy || vid == R.id.reboot) {
                t.setBackgroundResource(btnBg);
                t.setTextColor(sub);
            } else {
                t.setTextColor(sub);
            }
            return;
        }
        android.view.ViewGroup.LayoutParams lp = v.getLayoutParams();
        boolean pill = false;
        if (lp instanceof android.widget.LinearLayout.LayoutParams) {
            android.widget.LinearLayout.LayoutParams llp =
                    (android.widget.LinearLayout.LayoutParams) lp;
            if (llp.weight > 0 && (llp.width == 0 || llp.height <= dp(12))) pill = true;
        }
        if (pill) v.setBackgroundResource(dark ? R.drawable.pill_dark : R.drawable.pill_off);
    }

    private void installGlass() {
        try {
            View r = findViewById(R.id.root);
            if (!(r.getParent() instanceof android.view.ViewGroup)) return;
            android.view.ViewGroup parent = (android.view.ViewGroup) r.getParent();
            int[][] cfg = {{R.drawable.blob_green, -60, -80, 420},
                           {R.drawable.blob_blue, 300, 620, 460}};
            for (int i = 0; i < cfg.length; i++) {
                View b = new View(this);
                b.setBackgroundResource(cfg[i][0]);
                android.widget.FrameLayout.LayoutParams lp = new android.widget.FrameLayout.LayoutParams(
                        dp(cfg[i][3]), dp(cfg[i][3]));
                lp.leftMargin = dp(cfg[i][1]);
                lp.topMargin = dp(cfg[i][2]);
                b.setLayoutParams(lp);
                if (android.os.Build.VERSION.SDK_INT >= 31)
                    b.setRenderEffect(android.graphics.RenderEffect.createBlurEffect(
                            70f, 70f, android.graphics.Shader.TileMode.CLAMP));
                parent.addView(b, 0);
                float dx = (i % 2 == 0) ? 40f : -40f;
                b.animate().translationX(dx).translationY(dx / 2)
                        .setDuration(9000).setStartDelay(i * 400L)
                        .withEndAction(new Runnable() {
                            public void run() { }
                        }).start();
            }
        } catch (Throwable ignored) { }
    }

    private int dp(float v) {
        return (int) (v * getResources().getDisplayMetrics().density + 0.5f);
    }

    private void enterAnimation() {
        final View[] seq = {
                findViewById(R.id.statusCard),
                findViewById(R.id.start),
                findViewById(R.id.scroll),
                findViewById(R.id.reboot)
        };
        for (int i = 0; i < seq.length; i++) {
            final View v = seq[i];
            if (v == null) continue;
            v.setAlpha(0f);
            v.setTranslationY(i >= 1 ? 12f : 34f);
            v.animate().alpha(1f).translationY(0f)
                    .setStartDelay(90L * i).setDuration(i >= 1 ? 300 : 460)
                    .setInterpolator(new DecelerateInterpolator(1.6f)).start();
        }
    }

    /** 阶段点亮：回弹。 */
    private void sparkle(View v) {
        v.animate().scaleX(1.06f).scaleY(1.18f).setDuration(150)
                .setInterpolator(new DecelerateInterpolator())
                .withEndAction(new Runnable() {
                    public void run() {
                        v.animate().scaleX(1f).scaleY(1f).setDuration(200)
                                .setInterpolator(new DecelerateInterpolator()).start();
                    }
                }).start();
    }

    private void sayShizukuState() {
        if (!Shizuku.pingBinder()) {
            emit("Shizuku 未就绪：请先安装并启动 Shizuku（无线调试里授权它）", 0);
            return;
        }
        if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
            emit("Shizuku 已授权（版本 " + Shizuku.getVersion() + "）", 0);
        } else if (asked == 0) {
            asked = 1;
            emit("正在向 Shizuku 申请授权…", 0);
            Shizuku.requestPermission(1001);
        }
    }


    /** 沉浸式：内容画到状态栏/导航栏下面，浅色底配深色图标。 */
    private void immersive() {
        getWindow().setStatusBarColor(android.graphics.Color.TRANSPARENT);
        getWindow().setNavigationBarColor(android.graphics.Color.TRANSPARENT);
        View dv = getWindow().getDecorView();
        dv.setSystemUiVisibility(View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                | View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
                | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
    }

    /** 把内容往下让出状态栏高度，底部让出导航栏，避免被遮。 */
    private void applyInsets(View root) {
        int top = 0, bottom = 0;
        android.util.DisplayMetrics dm = getResources().getDisplayMetrics();
        int res = getResources().getIdentifier("status_bar_height", "dimen", "android");
        if (res > 0) top = getResources().getDimensionPixelSize(res);
        int nres = getResources().getIdentifier("navigation_bar_height", "dimen", "android");
        if (nres > 0) bottom = getResources().getDimensionPixelSize(nres);
        root.setPadding(root.getPaddingLeft(), top + (int) (12 * dm.density),
                root.getPaddingRight(), bottom);
    }

    /** 重启：优先走 Shizuku 的 shell 身份，其次 su。 */
    private long rebootArmedAt;
    private long forceRunAt;
    private long lateArmedAt;

    private long preWarnAt;
    static final String LOG_DIR = "/sdcard/Download/山茶内核工坊/日志";
    private volatile boolean parkedZombie;
    private volatile boolean legacyFailed;
    private IShizukuService svcRef;

    /* ---- 真实运行态（P0-1）：moduleLoaded() 的缓存，避免主线程做阻塞 IPC ---- */
    /** 已确认真实状态（至少回填过一次）。 */
    private volatile boolean stateChecked;
    /** 模块 kernelsu 在 /proc/modules 里 = 已接管。 */
    private volatile boolean stateTaken;
    /** 「启动链路」是否已锁死（已接管 / 已驻留 / 本次开机已跑过一轮）。 */
    private volatile boolean startLocked;
    /** 本次开机是否已经点过启动（持久化在 prefs，杀进程/重建实例都不解锁）。 */
    private volatile boolean runLocked;

    private void reboot() {
        // 已接管内核时：需要 4 秒内点第二次才真正重启，避免误触丢掉提权
        if (successDeclared || sawSuccess || moduleLoaded()) {
            long now = System.currentTimeMillis();
            if (now - rebootArmedAt > 4000) {
                rebootArmedAt = now;
                emit("已接管内核 · 重启会丢掉本次提权 —— 4 秒内再点一次「重启手机」即确认", 0);
                return;
            }
            emit("已确认 · 正在重启设备", 1);
        }
        emit("§ 请求重启系统", 0);
        new Thread(new Runnable() {
            public void run() {
                try {
                    if (Shizuku.pingBinder()
                            && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                        IShizukuService s2 = IShizukuService.Stub.asInterface(
                                new ShizukuBinderWrapper(Shizuku.getBinder()));
                        IRemoteProcess p2 = s2.newProcess(
                                new String[]{"sh", "-c", "svc power reboot || reboot"}, null, "/");
                        p2.waitFor();
                    } else {
                        Runtime.getRuntime().exec(new String[]{"sh", "-c", "su -c reboot"}).waitFor();
                    }
                } catch (Throwable t) {
                    emit("!! 重启失败：" + t + "（需要 Shizuku 或 root）", 0);
                }
            }
        }).start();
    }


    /** 本次开机的标识（当前时间 - 开机秒数）；开机秒数拿不到时返回 0 = 未知。 */
    private long bootId() {
        long up = uptimeSec();
        if (up <= 0) return 0;
        return System.currentTimeMillis() / 1000 - up;
    }

    /**
     * 开机秒数。
     *
     * 原实现解析失败直接 return -1，界面就打出“开机 -1 秒”。现在先读 /proc/uptime；
     * 读不到（权限/格式异常）用 SystemClock.elapsedRealtime() 兜底 —— 它本身就是开机
     * 以来的毫秒数；两条都拿不到才返回 -1，由界面显示“未知”，并且不参与链路判断。
     */
    private long uptimeSec() {
        try {
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.FileReader("/proc/uptime"));
            String line = r.readLine();
            r.close();
            if (line != null) {
                String[] p = line.trim().split("\\s+");
                if (p.length > 0 && !p[0].isEmpty()) {
                    long v = (long) Double.parseDouble(p[0]);
                    if (v >= 0) return v;
                }
            }
        } catch (Throwable ignored) { }
        try {
            long ms = android.os.SystemClock.elapsedRealtime();
            if (ms > 0) return ms / 1000;
        } catch (Throwable ignored) { }
        return -1;
    }

    /** 用 shell 身份确认 kernelsu 模块在不在。 */
    private boolean moduleLoaded() {
        try {
            IShizukuService s2 = IShizukuService.Stub.asInterface(
                    new ShizukuBinderWrapper(Shizuku.getBinder()));
            IRemoteProcess p2 = s2.newProcess(
                    new String[]{"sh", "-c", "grep -c kernelsu /proc/modules"}, null, "/");
            InputStream is = new android.os.ParcelFileDescriptor.AutoCloseInputStream(p2.getInputStream());
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(is));
            String v = r.readLine();
            p2.waitFor();
            return v != null && !v.trim().equals("0") && !v.trim().isEmpty();
        } catch (Throwable t) { return false; }
    }

    // ================= P0-1 真实运行态回填 =================

    /**
     * 用两个真实判据回填界面：
     *   ① moduleLoaded()  —— /proc/modules 里有没有 kernelsu（读失败退 Shizuku）
     *   ② pidof own127    —— 有没有驻留进程
     * 两者都在工作线程里做，结果回主线程上屏。
     */
    private void refreshRealState() {
        new Thread(new Runnable() {
            public void run() {
                boolean mod = false, alive = false;
                try { mod = moduleLoaded(); } catch (Throwable ignored) { }
                if (!mod) {
                    try { alive = remoteAlive(); } catch (Throwable ignored) { }
                }
                final boolean fm = mod, fa = alive;
                ui.post(new Runnable() {
                    public void run() {
                        try {
                            stateChecked = true;
                            stateTaken = fm;
                            if (running) return;      /* 正在跑：绝不覆盖实时界面 */
                            if (fm) applyUiTaken("模块 kernelsu 已在 /proc/modules 中 · 内核已接管，无需再启动");
                            else if (fa || loadParked())
                                applyUiParked("上次链路仍驻留（pidof own127 / 已落盘状态）· 请重启设备，不要重跑");
                            else applyUiIdle();
                        } catch (Throwable ignored) { }
                    }
                });
            }
        }).start();
    }

    /** 已接管：徽标「已接管」、标题「已接管 · 无需再启动」、进度 6/6、启动按钮置灰并锁死。 */
    private void applyUiTaken(final String why) {
        startLocked = true;
        stageIdx = 7;
        try {
            if (badge != null) {
                badge.setText("已接管");
                badge.setBackgroundResource(R.drawable.pill_on);
                badge.setTextColor(0xFFFFFFFF);
            }
            if (stage != null) stage.setText("已接管 · 无需再启动");
            if (progress != null) progress.setText("进度 6 / 6");
            if (hint != null) hint.setText(why);
            int[] ids = {R.id.p1, R.id.p2, R.id.p3, R.id.p4, R.id.p5, R.id.p6};
            for (int i = 0; i < ids.length; i++) {
                View v = findViewById(ids[i]);
                if (v != null) v.setBackgroundResource(R.drawable.pill_on);
            }
            lockStartButton("已接管 · 无需启动");
        } catch (Throwable ignored) { }
    }

    /** 有驻留进程但模块不在：拒绝重跑，明确要求重启。 */
    private void applyUiParked(final String why) {
        parkedZombie = true;
        startLocked = true;
        try {
            if (badge != null) {
                badge.setText("已驻留");
                badge.setBackgroundResource(R.drawable.pill_off);
                badge.setTextColor(0xFFD8623A);
            }
            if (stage != null) stage.setText("上次链路仍驻留 · 请重启设备");
            if (hint != null) hint.setText(why);
            lockStartButton("驻留中 · 需重启");
        } catch (Throwable ignored) { }
    }

    /** 两者都没有：正常待机。只有本轮没跑过才允许再点启动。 */
    private void applyUiIdle() {
        if (successDeclared || sawSuccess) return;
        try {
            badge.setText(runLocked ? "已启动过" : "待机");
            badge.setBackgroundResource(darkMode() ? R.drawable.pill_dark : R.drawable.pill_off);
            badge.setTextColor(darkMode() ? 0xFFA9BACC : 0xFF7387A0);
            stage.setText(runLocked ? "本次开机已启动过一轮" : "链路待机");
            if (hint != null)
                hint.setText(runLocked
                        ? "为避免重复往内核写，本次开机内不再允许启动；要重开请点底部「重启手机」"
                        : "自检 → 标定 → 定位 → 回收 → 落位 → 装载");
            if (runLocked) {
                startLocked = true;
                lockStartButton("本次开机已跑过");
            } else {
                startLocked = false;
                unlockStartButton();
            }
        } catch (Throwable ignored) { }
    }

    /** 把「启动链路」置灰：实心灰胶囊 + 灰字。
     *  注意：绝不能 animate().cancel() —— 入场动画是 translationY 12f→0，
     *  掐在半路会让按钮永久停在下方（看起来就是「往下移动、没对齐」）。
     *  这里只换背景与字色，不动位移/缩放/透明度。 */
    private void lockStartButton(String label) {
        try {
            final View b = findViewById(R.id.start);
            if (b == null) return;
            b.setBackgroundResource(R.drawable.pill_disabled);
            if (b instanceof TextView) ((TextView) b).setTextColor(0xFF8FA39A);
            b.setEnabled(true);
            ui.postDelayed(new Runnable() {
                public void run() {
                    try {
                        if (startLocked && !running) {
                            b.setBackgroundResource(R.drawable.pill_disabled);
                            if (b instanceof TextView) ((TextView) b).setTextColor(0xFF8FA39A);
                        }
                    } catch (Throwable ignored) { }
                }
            }, 1200);
        } catch (Throwable ignored) { }
    }

    /** 恢复「启动链路」到可点状态（绿胶囊 + 白字）。 */
    private void unlockStartButton() {
        try {
            View b = findViewById(R.id.start);
            if (b == null) return;
            b.setBackgroundResource(R.drawable.pill_on);
            if (b instanceof TextView) ((TextView) b).setTextColor(0xFFFFFFFF);
            b.setAlpha(1f);
            b.setTranslationY(0f);
            b.setScaleX(1f);
            b.setScaleY(1f);
        } catch (Throwable ignored) { }
    }

    /** 载荷进程是否驻留：优先 Shizuku，其次本机 sh（/proc 允许读时）。 */
    private boolean remoteAlive() {
        try {
            if (Shizuku.pingBinder()
                    && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                IShizukuService s2 = IShizukuService.Stub.asInterface(
                        new ShizukuBinderWrapper(Shizuku.getBinder()));
                IRemoteProcess p2 = s2.newProcess(new String[]{"sh", "-c",
                        "pidof own127 2>/dev/null | wc -w"}, null, "/");
                InputStream is = new android.os.ParcelFileDescriptor.AutoCloseInputStream(
                        p2.getInputStream());
                java.io.BufferedReader r = new java.io.BufferedReader(
                        new java.io.InputStreamReader(is));
                String v = r.readLine();
                r.close();
                p2.waitFor();
                String t = v == null ? "" : v.trim();
                if (!t.isEmpty() && !t.equals("0")) return true;
            }
        } catch (Throwable ignored) { }
        try {
            Process p = Runtime.getRuntime().exec(
                    new String[]{"/system/bin/sh", "-c", "pidof own127 2>/dev/null"});
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            String v = r.readLine();
            r.close();
            p.waitFor();
            return v != null && !v.trim().isEmpty();
        } catch (Throwable t) { return false; }
    }

    /** 只提示：KernelSU 管理器是否安装 / 版本（2.9 会检查；这里不自动安装）。 */
    private String ksuManagerInfo() {
        try {
            android.content.pm.PackageInfo pi =
                    getPackageManager().getPackageInfo("me.weishu.kernelsu", 0);
            return "已安装 · 版本 " + (pi.versionName == null ? "?" : pi.versionName)
                    + " (" + pi.versionCode + ")";
        } catch (Throwable t) { return null; }
    }

    /** 本次开机是否已点过启动（落盘，杀进程/重建实例都不解锁）。 */
    private boolean loadRunLock() {
        try {
            long bid = bootId();
            if (bid == 0) return false;
            return getSharedPreferences("ownctl", MODE_PRIVATE)
                    .getBoolean("run_locked", false)
                    && getSharedPreferences("ownctl", MODE_PRIVATE).getLong("run_locked_boot", 0) == bid;
        } catch (Throwable t) { return false; }
    }

    private void saveRunLock() {
        try {
            long bid = bootId();
            runLocked = true;
            getSharedPreferences("ownctl", MODE_PRIVATE).edit()
                    .putBoolean("run_locked", true)
                    .putLong("run_locked_boot", bid).apply();
        } catch (Throwable ignored) { }
    }

    /** 开机门闩：只有「同一次开机且已成功过」才允许拦，其余一律放行重试。 */
    private void markBootResult(boolean ok) {
        try {
            long bid = bootId();
            android.content.SharedPreferences.Editor e =
                    getSharedPreferences("ownctl", MODE_PRIVATE).edit();
            if (bid != 0) e.putLong("ran_boot", bid);
            e.putBoolean("ran_boot_ok", ok).apply();
        } catch (Throwable ignored) { }
    }

    /**
     * 日志链路自检（不执行任何载荷）：建会话文件 → 追加几行链路格式的文本 → 改名收尾。
     * 只用来验证「追加写不会留全 0 文件」「进行中会被改名」两件事，外部用
     * `am start --ez probe_log true` 触发。
     */
    private void selfTestLog() {
        new Thread(new Runnable() {
            public void run() {
                try {
                    startSession();
                    emit("· 自检 · 会话文件已建立（不执行载荷）", 0);
                    for (int i = 1; i <= 3; i++) {
                        narrate("S1|自检|自检行" + i + "|E000" + i + "|ok=1|probe=1");
                        try { Thread.sleep(1100); } catch (InterruptedException ignored) { }
                    }
                    narrate("S6|装载|自检收尾|E6080|ok=1|probe=1");
                    try { Thread.sleep(1200); } catch (InterruptedException ignored) { }
                    String fin = finishSession("自检-无载荷");
                    emit(fin != null ? "· 自检 · 会话已收尾改名 → " + fin : "· 自检 · 改名失败", fin != null ? 1 : 0);
                } catch (Throwable t) {
                    emit("· 自检失败：" + t, 0);
                }
            }
        }).start();
    }

    /** 提权成功后直接打开本机 KernelSU。 */
    private void openKsu() {
        new Thread(new Runnable() {
            public void run() {
                try {
                    if (Shizuku.pingBinder()
                            && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                        IShizukuService s2 = IShizukuService.Stub.asInterface(
                                new ShizukuBinderWrapper(Shizuku.getBinder()));
                        IRemoteProcess p = s2.newProcess(new String[]{"sh", "-c",
                                "am start -n me.weishu.kernelsu/.ui.MainActivity"}, null, "/");
                        java.io.BufferedReader r = new java.io.BufferedReader(
                                new java.io.InputStreamReader(
                                        new android.os.ParcelFileDescriptor.AutoCloseInputStream(
                                                p.getInputStream())));
                        String line;
                        while ((line = r.readLine()) != null) { }
                        p.waitFor();
                        emit("已拉起 KernelSU", 1);
                        return;
                    }
                } catch (Throwable ignored) { }
                try {
                    android.content.Intent i = getPackageManager()
                            .getLaunchIntentForPackage("me.weishu.kernelsu");
                    if (i != null) {
                        i.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
                        startActivity(i);
                        emit("已拉起 KernelSU", 1);
                    }
                } catch (Throwable t) {
                    emit("拉起 KernelSU 失败：" + t.getClass().getSimpleName(), 0);
                }
            }
        }).start();
    }

    /** 远端文件大小（不存在返回空串）。 */
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

    /** 远端文件是否与 assets 里那份逐字节一致（md5）。不存在/读不到一律返回 false。 */
    private boolean sameRemote(IShizukuService s2, String path, String asset) {
        String want = assetMd5(asset);
        if (want == null || want.isEmpty()) return false;
        return want.equalsIgnoreCase(remoteMd5(s2, path));
    }

    /** assets 里某个资源的 md5（十六进制小写）。 */
    private String assetMd5(String asset) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            InputStream in = getAssets().open(asset);
            byte[] b = new byte[65536];
            int n;
            while ((n = in.read(b)) > 0) md.update(b, 0, n);
            in.close();
            return hex(md.digest());
        } catch (Throwable t) { return null; }
    }

    /** 远端文件 md5；文件不存在时返回空串。 */
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

    private void pushAsset(IShizukuService s2, String asset, String dest, String mode)
            throws Exception {
        IRemoteProcess p = s2.newProcess(
                new String[]{"sh", "-c", "rm -f " + dest + "; cat > " + dest}, null, "/");
        OutputStream os = new android.os.ParcelFileDescriptor.AutoCloseOutputStream(
                p.getOutputStream());
        InputStream in = getAssets().open(asset);
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) os.write(buf, 0, n);
        os.close(); in.close();
        p.waitFor();
        IRemoteProcess c = s2.newProcess(new String[]{"sh", "-c",
                "chmod " + mode + " " + dest + "; ls -l " + dest + " | awk '{print $5}'"}, null, "/");
        java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(
                new android.os.ParcelFileDescriptor.AutoCloseInputStream(c.getInputStream())));
        String sz = r.readLine();
        c.waitFor();
        emit("灌入 " + asset + " → " + (sz == null ? "?" : sz.trim()) + " 字节", 1);
    }


    /**
     * 把链路原始输出转成我们自己的叙述：六段标题 + 关键事实，
     * 噪声（探针/逐条 plant 细节/请求回执）不进界面。
     */
    /** 按段号推进进度（不重复推进）。 */
    private void advanceTo(final int stage) {
        ui.post(new Runnable() {
            public void run() {
                try {
                    for (int i = 0; i < stage; i++) {
                        if (i < stage - 1 || true) { }
                    }
                    paintStageProgress(stage);
                } catch (Throwable ignored) { }
            }
        });
    }

    private int shownStage;
    private int tailDropped;

    private void paintStageProgress(int stage) {
        if (stage <= shownStage) return;          // 单调，不回退
        shownStage = stage;
        try {
            TextView pt = findViewById(R.id.progressText);
            if (pt != null) pt.setText("进度 " + stage + " / 6");
            String[] CIR2 = {"①", "②", "③", "④", "⑤", "⑥"};
            String[] NAME = {"自检", "标定", "定位", "回收", "落位", "装载"};
            TextView st = findViewById(R.id.stage);
            if (st != null && stage >= 1 && stage <= 6)
                st.setText(CIR2[stage - 1] + " · " + NAME[stage - 1]);
        } catch (Throwable ignored) { }
        try {
            int[] ids = {R.id.p1, R.id.p2, R.id.p3, R.id.p4, R.id.p5, R.id.p6};
            for (int i = 0; i < ids.length; i++) {
                View v = findViewById(ids[i]);
                if (v == null) continue;
                v.setBackgroundResource(i < stage ? R.drawable.pill_on : R.drawable.pill_off);
            }
        } catch (Throwable ignored) { }
    }

    private boolean successDeclared;
    private volatile boolean sawSuccess;
    private volatile long lastLineAt;
    private volatile boolean watchStop;

    /** 拿到 root 的第一时间关掉 panic_on_warn，避免内核 WARN 直接把机器重启。 */
    /** 拿到 root 第一时间关掉内核恐慌策略；逐级探测 su，并读回实际值。 */
    /** 提权成功：稳内核 + 显式宣告（不自动跳 KSU）。只执行一次。 */
    private void declareSuccess() {
        if (successDeclared) return;
        successDeclared = true;
        stateTaken = true;
        startLocked = true;
        getSharedPreferences("ownctl", MODE_PRIVATE).edit()
                .putString("last_ok_ver", verChoice()).apply();
        markBootResult(true);          /* 只有真成功才把本次开机标成 ok */
        ui.post(new Runnable() {
            public void run() {
                try {
                    /* 徽标/标题/进度/六段一次性置成「已接管」，并把启动按钮锁死 */
                    applyUiTaken("链路已接管内核 · 已驻留保活，无需再点启动");
                } catch (Throwable ignored) { }
                emit("════════════════════════", 1);
                emit("✅ 提权成功 · 已获得 root（KernelSU 已接管内核）", 1);
                String[] bp = boundPayload();
                long up2 = uptimeSec();
                emit("版本 " + verChoice() + " · 载荷 sha " + (bp == null ? "?" : bp[1].substring(0, 12) + "…")
                        + (up2 > 0 ? " · 开机 " + up2 + " 秒" : ""), 1);
                emit("════════════════════════", 1);
                emit("· 结束 · 链路已保活驻留（无需再点启动）", 1);
                running = false;                 // 允许界面回到可用状态
                stopBreathe();
                try { setTitleStageDone(); } catch (Throwable ignored) { }
            }
        });
        new Thread(new Runnable() {
            public void run() {
                calmKernel();
                for (int i = 0; i < 3; i++) {
                    if (moduleLoaded()) { emit("内核模块在线确认", 1); break; }
                    try { Thread.sleep(800); } catch (InterruptedException ignored) { }
                }
                emit("提权已完成 · 需要时请自行打开 KernelSU", 1);
            }
        }).start();
        /* 成功收尾：等 1.5s 让收尾行先被读到，再走统一 endRun。
           killIfFailed=false —— 成功路径绝不碰进程（pause 驻留，杀了 UAF）。 */
        new Thread(new Runnable() {
            public void run() {
                try { Thread.sleep(1500); } catch (InterruptedException ignored) { }
                endRun("成功", verChoice().isEmpty() ? "unknown" : verChoice(), -1, false);
            }
        }).start();
    }

    private void setTitleStageDone() {
        TextView st = findViewById(R.id.stage);
        if (st != null) st.setText("⑥ · 装载 · 已完成");
        TextView pt = findViewById(R.id.progressText);
        if (pt != null) pt.setText("进度 6 / 6 · 已接管");
    }

    private void calmKernel() {
        for (int att = 1; att <= 6; att++) {
            if (calmOnce()) return;
            try { Thread.sleep(1000); } catch (InterruptedException ignored) { }
        }
        emit("关闭内核恐慌策略失败（su 6 次重试均未成功）", 0);
    }

    private boolean calmOnce() {
        // 关键：用 Shizuku(shell) 身份去 su —— app uid 直接 su 会被 KSU 拒绝
        String cmd = "su -c 'echo 0 > /proc/sys/kernel/panic_on_warn; "
                   + "echo 0 > /proc/sys/kernel/panic_on_oops; "
                   + "cat /proc/sys/kernel/panic_on_warn'";
        try {
            if (Shizuku.pingBinder()
                    && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                IShizukuService svc = IShizukuService.Stub.asInterface(
                        new ShizukuBinderWrapper(Shizuku.getBinder()));
                IRemoteProcess rp = svc.newProcess(new String[]{"sh", "-c", cmd}, null, "/");
                java.io.BufferedReader r = new java.io.BufferedReader(
                        new java.io.InputStreamReader(
                                new android.os.ParcelFileDescriptor.AutoCloseInputStream(
                                        rp.getInputStream())));
                String v = r.readLine();
                rp.waitFor();
                try { r.close(); } catch (Throwable ignored) { }
                try { rp.destroy(); } catch (Throwable ignored) { }
                if (v != null && v.trim().equals("0")) {
                    emit("已关闭内核恐慌策略（panic_on_warn=0 via Shizuku+su）", 1);
                    return true;
                }
                emit("shizuku-su 读回=" + v, 0);
            }
        } catch (Throwable t) {
            emit("shizuku-su 异常：" + t.getClass().getSimpleName(), 0);
        }
        // 回退：直接 su（部分机型允许）
        for (String su : new String[]{"su", "/system/bin/su"}) {
            try {
                Process pr = Runtime.getRuntime().exec(new String[]{"sh", "-c",
                        su + " -c " + "\"" + "echo 0 > /proc/sys/kernel/panic_on_warn; cat /proc/sys/kernel/panic_on_warn" + "\""});
                java.io.BufferedReader r = new java.io.BufferedReader(
                        new java.io.InputStreamReader(pr.getInputStream()));
                String v = r.readLine();
                pr.waitFor();
                if (v != null && v.trim().equals("0")) {
                    emit("已关闭内核恐慌策略（via " + su + "）", 1);
                    return true;
                }
            } catch (Throwable ignored) { }
        }
        return false;
    }

    /** 7879 槽位用的是 2.9 原版载荷，它的日志是方括号标签格式，单独解析。 */
    private boolean legacyLog() {
        return "7879".equals(verChoice());
    }

    /** 7879 走 2.9 原版载荷：原样输出，只按关键词着色，不做改写。 */
    private void narrateLegacy(String l) {
        // 2.9 的判定：日志出现 "[gate127] SUCCESS" 即成功；"[gate127] done ok=0" 为失败标记
        if (l.contains("[gate127] SUCCESS")) sawSuccess = true;
        if (l.contains("[gate127] done ok=0")) legacyFailed = true;
        if (l.contains("parking without reap") || l.contains("no verified slide")
                || l.contains("do not kill this process")) {
            parkedZombie = true;
            emit(l, 0);
            emit("· 老链路已进入僵尸驻留（持有页）—— 不要中止、不要杀进程，请重启设备", 0);
            return;
        }
        boolean bad = l.contains("failed") || l.contains("FAILED")
                || l.contains("ok=0") || l.contains("errno=-");
        if (l.contains("gate127") && l.contains("SUCCESS")) sawSuccess = true;
        emit(l, bad ? 0 : 1);
    }

    private void narrate(String raw) {
        String l = raw == null ? "" : raw.trim();
        if (l.isEmpty()) return;

        // 自研语法：S<n>|段名|动作|事件码|k=v…   与 D|… 调试通道
        synchronized (liveBuf) {
            liveBuf.append(l).append('\n');
            /* 长跑（7879 观察窗 300s）时给缓冲设上限，超了裁头并同步已写偏移 */
            if (liveBuf.length() > 524288) {
                int cut = 262144;
                liveBuf.delete(0, cut);
                liveWritten = Math.max(0, liveWritten - cut);
            }
        }
        flushLive();
        if (legacyLog()) { narrateLegacy(l); return; }
        if (l.startsWith("D|")) return;
        if (sawSuccess && l.contains("E6121")) {
            emit("· 保活已结束（收到信号）", 0);
            return;
        }
        if (l.contains("E6081") && sawSuccess && !successDeclared) {
            emit("· 收尾 · 链路已自行收束（E6081）", 0);
            declareSuccess();
            return;
        }
        if (l.startsWith("S") && l.indexOf('|') > 0 && l.indexOf('|') < 4) {
            // 原样显示链路自己的输出，前置段号圆标便于阅读
            String[] CIR = {"①", "②", "③", "④", "⑤", "⑥"};
            int sn = 0;
            try { sn = Integer.parseInt(l.substring(1, l.indexOf('|'))); } catch (Throwable ignored) { }
            String mark = (sn >= 1 && sn <= 6) ? CIR[sn - 1] + " " : "";
            boolean bad1 = l.contains("ok=0");
            boolean done = l.contains("E6080") && l.contains("ok=1");
            if (sawSuccess && sn > 0 && sn < 6) {
                // 成功后的回收重试属于“收尾”，逐条显示只会误导，这里折叠
                if (tailDropped == 0)
                    emit("· 收尾中 · 已成功的链路正在静默退出（后续无效重试不再显示）", 1);
                tailDropped++;
                return;
            }
            emit(mark + l, bad1 ? 0 : 1);
            if (done) { sawSuccess = true; emit("· 装载完成 · 进入收尾", 1); }   // 先记账，等全流程跑完再宣告
            try {
                int idx = Integer.parseInt(l.substring(1, l.indexOf('|')));
                if (idx >= 1 && idx <= 6) advanceTo(idx);
            } catch (Throwable ignored) { }
            return;
        }

        // 噪声：直接吞掉，不占界面
        if (l.matches("[·.\\-—=+*/_ ]+") || l.equals("PRE") || l.startsWith("PRE ") || l.contains("[probe]") || l.contains("[txt]") || l.contains("per-cpu")
                || l.contains("plant1 target=") || l.contains("[plant] req done")
                || l.contains("padding") || l.contains("kmem_cache_alloc")
                || l.contains("slab padding=")) return;

        if (l.contains("init_module rc=0") || l.contains("[al] init_module")) {
            emit("⑥ 装载 · 已完成，内核开始接管（rc=0）", 1);
            return;
        }
        if (l.contains("khs_num") && l.contains("now='1'")) {
            emit("⑥ 装载 · 放行开关已打开", 1);
            return;
        }
        if (l.contains("g(7) cleared") || l.contains("g(7) 已清")) {
            emit("⑥ 装载 · 安全门已解除（g7 归零）", 1);
            return;
        }
        if (l.contains("gate127] SUCCESS")) {
            emit("✔ 全部完成 · 内核已接管，可以直接用 root 了", 1);
            return;
        }
        if (l.contains("fake cred A=")) {
            emit("⑤ 落位 · 身份替身已就绪", 1);
            return;
        }
        if (l.contains("uid repair done") || l.contains("uid repair OK")) {
            emit("⑤ 落位 · 身份数字已对齐（uid/gid 全部归零）", 1);
            return;
        }
        if (l.contains("plant1 V=") && l.contains("slab_own=31/31")) {
            emit("④ 回收 · 已拿到目标内存页（同页 31/31）", 1);
            return;
        }
        if (l.contains("burst hit=1")) {
            emit("④ 回收 · 内存页已归还，等内核复用", 1);
            return;
        }
        if (l.contains("slide=")) {
            emit("② 标定 · 已定位内核起始地址", 0);
            return;
        }
        if (l.contains("[cred]")) {
            emit("③ 定位 · 已找到身份信息所在页", 0);
            return;
        }
        if (l.contains("[check]")) {
            emit("① 自检 · 通道正常，可以开始", 0);
            return;
        }
        if (l.contains("victim not captured") || l.contains("exhausted")
                || l.contains("FAILED") || l.contains("not zero")) {
            emit("· 这一小步没命中，自动重试中…", 0);
            return;
        }
        // 其余：去掉原始方括号标签；纯符号行直接丢弃，不再画圆点
        String clean = l.replaceAll("\\[[a-z0-9_]+\\]\\s*", "").trim();
        if (clean.isEmpty() || clean.matches("[·.\\-—=+*/_ ]+")) return;
        emit(clean, 0);
    }

    private void pressFx(final View v) {
        /* 按压反馈交给系统 ripple，不再叠一层缩放，避免手感发硬 */
        v.setClickable(true);
    }

    /** 轻到几乎察觉不到的回弹，只用来给"点到了"一个交代。 */
    private void bounce(View v) {
        v.animate().scaleX(0.985f).scaleY(0.985f).setDuration(90)
                .setInterpolator(new DecelerateInterpolator())
                .withEndAction(new Runnable() {
                    public void run() {
                        v.animate().scaleX(1f).scaleY(1f).setDuration(170)
                                .setInterpolator(new DecelerateInterpolator()).start();
                    }
                }).start();
    }

    /**
     * 日志区独立滚动。
     *
     * 根因：日志 TextView 之前挂着 android:textIsSelectable="true"，这会让它变成
     * clickable/focusable，ACTION_DOWN 被它自己吃掉 —— ViewGroup 一旦有子 View 消费了
     * DOWN 就不会再走自己的 onTouchEvent，于是内层 ScrollView(id=scroll) 既收不到
     * 事件、也永远不会成为触摸目标（所以挂在 scroll 上的 OnTouchListener 从头到尾没被
     * 调用过一次，requestDisallowInterceptTouchEvent 自然也白设）；手势最终被外层页面
     * ScrollView 的 onInterceptTouchEvent 抢走，只剩整页在动。
     *
     * 现在：日志只负责显示（复制按钮取 raw 文本），手势交给内层 ScrollView；
     * 日志还能往当前方向滚时，把所有祖先的拦截都关掉；滚到边界再把页面滚动交还外层。
     */
    private void installLogScroll() {
        if (log != null) {
            try {
                log.setTextIsSelectable(false);
                log.setClickable(false);
                log.setLongClickable(false);
                log.setFocusable(false);
                log.setFocusableInTouchMode(false);
                log.setMovementMethod(null);          /* 不再用 ScrollingMovementMethod 兜滚动 */
                log.setVerticalScrollBarEnabled(false); /* TextView 自身滚动条会触发 ScrollBarDrawable NPE */
                log.setHorizontalScrollBarEnabled(false);
                log.setBackgroundColor(0x00000000);
            } catch (Throwable ignored) { }
        }
        if (scroll == null) return;
        try {
            scroll.setFillViewport(false);
            scroll.setVerticalScrollBarEnabled(true);   /* 内层 ScrollView 的滚动条保留，提示还能滚 */
            scroll.setScrollBarStyle(View.SCROLLBARS_INSIDE_OVERLAY);
            scroll.setOnTouchListener(new View.OnTouchListener() {
                private float downY;
                public boolean onTouch(View v, MotionEvent e) {
                    try {
                        switch (e.getActionMasked()) {
                            case MotionEvent.ACTION_DOWN:
                                downY = e.getY();
                                /* 内容不足一屏时直接让页面滚 */
                                holdPage(v, v.canScrollVertically(-1) || v.canScrollVertically(1));
                                break;
                            case MotionEvent.ACTION_MOVE: {
                                float dy = e.getY() - downY;
                                if (dy > dp(8))       { followLog = false; holdPage(v, v.canScrollVertically(-1)); }
                                else if (dy < -dp(8)) holdPage(v, v.canScrollVertically(1));
                                else                  holdPage(v, true);
                                break;
                            }
                            case MotionEvent.ACTION_UP:
                            case MotionEvent.ACTION_CANCEL:
                                /* 松手时按真实位置决定要不要继续跟随：回到底部就恢复跟随 */
                                followLog = !v.canScrollVertically(1);
                                holdPage(v, false);
                                break;
                        }
                    } catch (Throwable ignored) { }
                    return false;    /* 返回 false，继续交给 ScrollView 自己滚 */
                }
            });
        } catch (Throwable ignored) { }
    }

    /** hold=true：要求所有祖先都不要抢手势；false：把页面滚动还给外层。 */
    private void holdPage(View v, boolean hold) {
        ViewParent p = v.getParent();
        for (int i = 0; p != null && i < 32; i++) {
            p.requestDisallowInterceptTouchEvent(hold);
            p = p.getParent();
        }
    }

    /**
     * 跟随最新一行。
     *
     * 日志不跟着滚的根因：这里原来在 post 里用
     * scroll.getScrollY() + getHeight() &gt;= log.getHeight() 判断“是否在底部”，
     * 但 append 和 post 发生在同一条 UI 消息里，回调执行时新文本还没参与布局，
     * log.getHeight() 还是旧值 —— 第一行就被判成“在底部”，fullScroll 作用在旧高度上，
     * 紧随其后的布局又把内容撑高，视图再也不是底部；下一行比较时高度已经变大，
     * 于是判成“不在底部”，从此整段链路都不再滚动。
     *
     * 现在：跟不跟随由 followLog 决定（只有用户往上翻历史才停），滚动延迟一帧执行，
     * 等这次 append 的布局完成后再滚到底。
     */
    private void autoScroll() {
        if (scroll == null || log == null || !followLog || scrollPending) return;
        scrollPending = true;
        scroll.postDelayed(new Runnable() {
            public void run() {
                scrollPending = false;
                try { if (followLog) scroll.fullScroll(View.FOCUS_DOWN); }
                catch (Throwable ignored) { }
            }
        }, 16);
    }

    /** 统一日志出口：先记账（hist/raw），再交给 UI 线程绘制。 */
    private void emit(final String rawLine, final int kind) {
        /* P1-7：emit 只负责界面与 hist/raw 记账，绝不写 liveBuf ——
           实时日志文件只收链路输出（narrate/narrateLegacy），否则 UI 文案会把现场证据冲掉。 */
        if (log == null) return;
        final String line = rawLine == null ? "" : rawLine.replaceAll("^[ \\t]+", "");
        if (line.isEmpty()) return;
        final long when = System.currentTimeMillis();
        synchronized (hist) {
            if (hist.size() >= 2000) { hist.remove(0); histKind.remove(0); histTime.remove(0); }
            hist.add(line);
            histKind.add(Integer.valueOf(kind));
            histTime.add(Long.valueOf(when));
        }
        ui.post(new Runnable() {
            public void run() {
                String stageTag = renderLine(line, kind, when);
                raw.append(line).append('\n');
                if (raw.length() > 120000) raw.delete(0, raw.length() - 100000);
                if (lineCount > 0 && lineCount >= 1500) { log.setText(""); lineCount = 0; }
                lineCount++;
                autoScroll();
                if (stageTag != null) advance(stageTag);
            }
        });
    }

    /** 按当前主题画一行（只画，不记账）；返回该行命中的阶段标签，没有则 null。 */
    private String renderLine(String line, int kind, long when) {
        if (log == null) return null;
        String stageTag = null;
        for (String[] row : STAGE) {
            if (line.contains(row[0])) { stageTag = row[1]; break; }
        }
        int color = C_MSG;
        if (kind == 1 || line.contains("ok=1") || line.contains("SUCCESS")
                || line.contains("rc=0") || line.contains("MODULE LOADED"))
            color = C_OK;
        else if (line.contains("ok=0") || line.contains("failed") || line.contains("errno=")
                || line.contains("BLOCKED") || line.contains("miss"))
            color = C_BAD;
        else if (line.contains("[probe]") || line.contains("[txt]") || line.contains("per-cpu")
                || line.contains("plant1 target="))
            color = C_DIM;

        SpannableStringBuilder sb = new SpannableStringBuilder();
        int at = sb.length();
        sb.append(ts.format(new Date(when))).append("  ");
        sb.setSpan(new ForegroundColorSpan(C_TIME), at, sb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        if (stageTag != null) {
            at = sb.length();
            sb.append(stageTag).append("  ");
            sb.setSpan(new ForegroundColorSpan(C_STAGE), at, sb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            sb.setSpan(new StyleSpan(Typeface.BOLD), at, sb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        at = sb.length();
        sb.append(line).append('\n');
        sb.setSpan(new ForegroundColorSpan(color), at, sb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        log.append(sb);
        return stageTag;
    }

    private void advance(String tag) {
        int idx = 0;
        if (tag.startsWith("①")) idx = 1;
        else if (tag.startsWith("②")) idx = 2;
        else if (tag.startsWith("③")) idx = 3;
        else if (tag.startsWith("④")) idx = 4;
        else if (tag.startsWith("⑤")) idx = 5;
        else if (tag.startsWith("⑥")) idx = 6;
        else if (tag.equals("完成")) idx = 7;
        if (idx <= stageIdx) return;
        stageIdx = idx;
        for (int i = 0; i < 6; i++) {
            final View p = pills[i];
            if (i < Math.min(idx, 6)) {
                p.setBackgroundResource(R.drawable.pill_on);
                sparkle(p);
            }
        }
        int t = Math.min(idx, 6);
        stage.setText(t >= 6 ? "⑥ · 门控解除与装载" : new String[]{
                "", "① · 通道自检", "② · 基线标定", "③ · 凭据页定位",
                "④ · 页回收", "⑤ · 凭据页落位"}[t]);
        progress.setText("进度 " + Math.min(idx, 6) + " / 6");
        if (idx >= 7) {
            badge.setText("在线");
            badge.setBackgroundResource(R.drawable.pill_on);
            badge.setTextColor(0xFFFFFFFF);
        }
    }

    private void startBreathe() {
        breathe = ObjectAnimator.ofFloat(stage, "alpha", 1f, 0.55f, 1f);
        breathe.setDuration(1600);
        breathe.setRepeatCount(ValueAnimator.INFINITE);
        breathe.setInterpolator(new AccelerateDecelerateInterpolator());
        breathe.start();
    }

    private void stopBreathe() {
        if (breathe != null) { breathe.cancel(); stage.setAlpha(1f); breathe = null; }
    }

    /** 官方内置两支载荷：3666（新内核）/ 7879（旧内核）。必选。 */
    /** 版本 → 资产名 / 体积 / sha256 —— 运行前逐字节校验，保证"选哪个就跑哪个"。 */
    static final String[][] VER_SHA = {
            {"3666", "own127",      "532280", "8038F24F0A39E7628ED8CBD4AD26FA658D99ECA762CFD411AA1610AF11A083C5"},
            {"7879", "own127_prev", "527672", "EA78013468BD0C8FCCF5CEDB030A08D9162D450757288EE5CAC15185B75B43D2"},
    };

    private java.util.List<String[]> manifestList;

    /** 运行时清单（外置优先），元素 {id,asset,size,sha,label,kernel}。 */
    private java.util.List<String[]> manifest() {
        if (manifestList == null) {
            manifestList = Payloads.loadManifest(this);
            if (manifestList == null) {
                java.util.List<String[]> fb = new java.util.ArrayList<>();
                for (String[] r : VER_SHA)
                    fb.add(new String[] { r[0], r[1], r[2], r[3],
                            r[0].equals("7879") ? "7879 · 旧内核" : "3666 · 新内核",
                            r[0].equals("7879") ? "6.6.127 / abogki…7879" : "6.6.127 / abogki573773666" });
                manifestList = fb;
            }
        }
        return manifestList;
    }

    static final String[][] VER = {
            {"3666", "3666 · 新内核", "6.6.127 / abogki573773666"},
            {"7879", "7879 · 旧内核", "6.6.127 / abogki...7879"},
    };

    private String verChoice() {
        return getSharedPreferences("ownctl", MODE_PRIVATE).getString("payload_ver", "");
    }

    private void bindVersionPicker() {
        final TextView pick = findViewById(R.id.verPick);
        if (pick == null) return;
        refreshVerLabel(pick);
        pick.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                bounce(v);
                showVersionMenu(pick);
            }
        });
    }

    private void refreshVerLabel(TextView pick) {
        String c = verChoice();
        if (c.isEmpty()) {
            pick.setText("请选择 · 3666（新内核） / 7879（旧内核）");
        } else {
            for (String[] r : VER)
                if (r[0].equals(c)) pick.setText("已选 · " + r[1]);
        }
    }

    private void showVersionMenu(final TextView anchor) {
        final android.app.Dialog dlg = new android.app.Dialog(this);
        dlg.requestWindowFeature(android.view.Window.FEATURE_NO_TITLE);

        final android.widget.LinearLayout box = new android.widget.LinearLayout(this);
        box.setOrientation(android.widget.LinearLayout.VERTICAL);
        box.setBackgroundResource(R.drawable.menu_bg);
        int pad = (int) (12 * getResources().getDisplayMetrics().density);
        box.setPadding(pad, pad, pad, pad);

        android.widget.TextView head = new android.widget.TextView(this);
        head.setText("选择链路版本");
        head.setTextSize(12f);
        head.setTextColor(0xFF7C8B84);
        head.setPadding(pad / 2, pad / 3, pad / 2, pad / 2);
        box.addView(head);

        String cur = verChoice();
        String lastOk = getSharedPreferences("ownctl", MODE_PRIVATE).getString("last_ok_ver", "");
        for (final String[] row : manifest()) {
            android.widget.LinearLayout item = new android.widget.LinearLayout(this);
            item.setOrientation(android.widget.LinearLayout.HORIZONTAL);
            item.setGravity(android.view.Gravity.CENTER_VERTICAL);
            item.setBackgroundResource(row[0].equals(cur)
                    ? R.drawable.menu_item_sel : R.drawable.menu_item_bg);
            int ip = (int) (14 * getResources().getDisplayMetrics().density);
            item.setPadding(ip, ip, ip, ip);

            android.widget.ImageView dot = new android.widget.ImageView(this);
            dot.setImageResource(row[0].equals(cur) ? R.drawable.dot_on : R.drawable.dot_off);
            android.widget.LinearLayout.LayoutParams dlp = new android.widget.LinearLayout.LayoutParams(
                    (int) (10 * getResources().getDisplayMetrics().density),
                    (int) (10 * getResources().getDisplayMetrics().density));
            dlp.rightMargin = ip / 2;
            item.addView(dot, dlp);

            android.widget.LinearLayout texts = new android.widget.LinearLayout(this);
            texts.setOrientation(android.widget.LinearLayout.VERTICAL);
            TextView t1 = new TextView(this);
            t1.setText(row[4] + (row[0].equals(lastOk) ? "  ✓ 上次成功" : ""));
            t1.setTextSize(15f);
            t1.setTextColor(0xFF22302B);
            TextView t2 = new TextView(this);
            t2.setText(row[5]);
            t2.setTextSize(11f);
            t2.setTextColor(0xFF8CA096);
            texts.addView(t1);
            texts.addView(t2);
            item.addView(texts, new android.widget.LinearLayout.LayoutParams(
                    0, android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

            item.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    getSharedPreferences("ownctl", MODE_PRIVATE).edit()
                            .putString("payload_ver", row[0]).apply();
                    refreshVerLabel(anchor);
                    emit("链路版本已选定 · " + row[4] + "（" + row[5] + "）", 1);
                    dlg.dismiss();
                }
            });
            android.widget.LinearLayout.LayoutParams ilp = new android.widget.LinearLayout.LayoutParams(
                    android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                    android.widget.LinearLayout.LayoutParams.WRAP_CONTENT);
            ilp.topMargin = ip / 4;
            ilp.bottomMargin = ip / 4;
            box.addView(item, ilp);
        }

        dlg.setContentView(box);
        android.view.Window w = dlg.getWindow();
        if (w != null) {
            w.setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(0x00000000));
            w.setLayout(android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                    android.view.ViewGroup.LayoutParams.WRAP_CONTENT);
            w.setGravity(android.view.Gravity.CENTER);
            w.getAttributes().windowAnimations = 0;
        }
        dlg.show();
    }

    /** 返回 {资产名, sha256, 体积}；未选择返回 null。 */
    private String[] boundPayload() {
        String c = verChoice();
        if (c.isEmpty()) return null;
        for (String[] r : manifest())
            if (r[0].equals(c)) return new String[] { r[1], r[3], r[2] };
        return null;
    }

    /** 把链路日志保存到 Download/山茶内核工坊/日志，返回可见路径（失败返回 null）。 */
    // ---- 实时日志：固定文件持续覆盖，重启后仍能在目录里找回 ----
    private static final String LIVE_NAME = "实时日志-最近一次.txt";
    private final StringBuilder liveBuf = new StringBuilder();
    private android.net.Uri liveUri;
    private long sessionId = -1;
    private String sessionStart = "";
    private String sessionVer = "";
    private volatile long lastLiveFlush;

    private android.net.Uri ensureLiveUri() {
        if (liveUri != null) return liveUri;
        try {
            String rel = android.os.Environment.DIRECTORY_DOWNLOADS + "/山茶内核工坊/日志";
            android.net.Uri col = android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI;
            android.database.Cursor c = getContentResolver().query(col,
                    new String[]{android.provider.MediaStore.MediaColumns._ID},
                    android.provider.MediaStore.MediaColumns.DISPLAY_NAME + "=? AND "
                            + android.provider.MediaStore.MediaColumns.RELATIVE_PATH + "=?",
                    new String[]{LIVE_NAME, rel + "/"}, null);
            if (c != null) {
                if (c.moveToFirst()) {
                    long id = c.getLong(0);
                    c.close();
                    liveUri = android.content.ContentUris.withAppendedId(col, id);
                    return liveUri;
                }
                c.close();
            }
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, LIVE_NAME);
            cv.put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "text/plain");
            cv.put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH, rel);
            liveUri = getContentResolver().insert(col, cv);
        } catch (Throwable ignored) { }
        return liveUri;
    }

    /** 新一轮开始：建一个“进行中”的独立文件，并立刻把 header 落盘（绝不留下 0 字节文件）。 */
    private void startSession() {
        liveWritten = 0;
        liveHeader = false;
        lastLiveFlush = 0;
        liveUri = null;
        sessionId = -1;
        try {
            sessionVer = verChoice().isEmpty() ? "unknown" : verChoice();
            sessionStart = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss",
                    java.util.Locale.US).format(new java.util.Date());
            String name = "进行中-" + sessionStart + "-" + sessionVer + ".txt";
            String rel = android.os.Environment.DIRECTORY_DOWNLOADS + "/山茶内核工坊/日志";
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, name);
            cv.put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "text/plain");
            cv.put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH, rel);
            liveUri = getContentResolver().insert(
                    android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
            if (liveUri != null) sessionId = android.content.ContentUris.parseId(liveUri);
        } catch (Throwable ignored) { }
        /* 成败都要写 prefs：失败写 -1，避免 finishSession 去改上一轮的文件（P2-8） */
        try {
            getSharedPreferences("ownctl", MODE_PRIVATE).edit()
                    .putLong("session_id", sessionId)
                    .putString("session_start", sessionStart)
                    .putString("session_ver", sessionVer).apply();
        } catch (Throwable ignored) { }
        if (sessionId > 0) {
            /* header 必须抢在任何一行链路输出之前落盘，否则首行会跑到 header 前面。
               这里同步写一次（一次小写入，与前面的 insert 同量级），写完再放开 flushLive。 */
            liveHeader = true;
            if (!appendLive("", true)) appendLive("", true);
        } else {
            liveHeader = false;
        }
    }

    /** 结束本轮：把“进行中”改名为「时间_版本_结果」。 */
    private String finishSession(String outcome) {
        try {
            long id = sessionId;
            String st = sessionStart, ver = sessionVer;
            if (id <= 0 || st.isEmpty()) {
                id = getSharedPreferences("ownctl", MODE_PRIVATE).getLong("session_id", -1);
                st = getSharedPreferences("ownctl", MODE_PRIVATE).getString("session_start", "");
                ver = getSharedPreferences("ownctl", MODE_PRIVATE).getString("session_ver", "unknown");
            }
            if (id <= 0) return null;
            String niceStart = st.length() >= 15
                    ? st.substring(0, 4) + "-" + st.substring(4, 6) + "-" + st.substring(6, 8)
                      + "_" + st.substring(9, 11) + "-" + st.substring(11, 13) + "-" + st.substring(13, 15)
                    : st;
            String name = niceStart + "_" + ver + "_" + outcome + ".txt";
            android.content.ContentValues cv = new android.content.ContentValues();
            cv.put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, name);
            android.net.Uri u = android.content.ContentUris.withAppendedId(
                    android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, id);
            int n = getContentResolver().update(u, cv, null, null);
            if (n > 0) {
                liveUri = null; sessionId = -1;
                liveWritten = 0; liveHeader = false;
                getSharedPreferences("ownctl", MODE_PRIVATE).edit()
                        .putLong("session_id", -1).apply();
                return "/sdcard/Download/山茶内核工坊/日志/" + name;
            }
            /* 改名失败：保留 prefs 里的 session 记录，下次启动由 recoverLastRun 再试一次（P2-10） */
        } catch (Throwable ignored) { }
        return null;
    }

    /**
     * 追加写入实时日志（每 1 秒一次，只写增量）。
     *
     * P1-5/P1-6 的根因是 "wt" 先截断再全量写：中途掉电就留下全 0x00 文件，
     * 正常结束时又会把上一轮的现场覆盖掉。现在改成：
     *   · "wa" 追加，永不截断 → 任何失败最多留半行，不会出现全 0 文件；
     *   · 每个会话的第一笔先写 header（首行标记），后续只写增量；
     *   · 写失败重试一次，仍失败也只丢这一块增量。
     */
    private int liveWritten;        /* 已写入文件的字符数（相对当前 liveBuf） */
    private boolean liveHeader;     /* 本会话 header 是否已落盘 */

    private void flushLive() {
        long now = System.currentTimeMillis();
        if (now - lastLiveFlush < 1000) return;
        lastLiveFlush = now;
        final String delta;
        final boolean needHead;
        synchronized (liveBuf) {
            int len = liveBuf.length();
            if (len <= liveWritten) return;
            delta = liveBuf.substring(liveWritten);
            liveWritten = len;
        }
        needHead = !liveHeader;
        liveHeader = true;
        new Thread(new Runnable() {
            public void run() {
                if (appendLive(delta, needHead)) return;
                /* 失败重试一次：只重发这一块增量 */
                if (!appendLive(delta, needHead))
                    android.util.Log.w("ownctl", "live append failed, dropped "
                            + delta.length() + " chars");
            }
        }).start();
    }

    /** 追加一块增量（可选带 header）。返回是否成功。 */
    private boolean appendLive(String delta, boolean withHead) {
        try {
            android.net.Uri u = ensureLiveUri();
            if (u == null) return true;      /* 没有目标文件：不算失败，别反复重试 */
            java.io.OutputStream os = null;
            try { os = getContentResolver().openOutputStream(u, "wa"); } catch (Throwable ignored) { }
            if (os == null) os = getContentResolver().openOutputStream(u);   /* 兜底：默认 rw */
            if (os == null) return false;
            if (withHead) {
                String head = "# 山茶 · 内核工坊 实时日志（追加写 · 首行标记）\n"
                        + "# HEADER append v8.0 · 版本 " + verChoice() + " · "
                        + new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss",
                                java.util.Locale.US).format(new java.util.Date()) + "\n"
                        + "# ---- 链路输出 ----\n";
                os.write(head.getBytes("UTF-8"));
            }
            if (!delta.isEmpty()) os.write(delta.getBytes("UTF-8"));
            os.flush();
            try { os.close(); } catch (Throwable ignored) { }
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private String saveLog(String tag) {
        try {
            if (!Shizuku.pingBinder()) return null;
            IShizukuService svc0 = IShizukuService.Stub.asInterface(
                    new ShizukuBinderWrapper(Shizuku.getBinder()));
            String src = "7879".equals(verChoice())
                    ? "/data/local/tmp/own127.log" : "/data/local/tmp/cve-2026-98260.log";

            // 1) 通过 shell 读出日志正文（避免 app 无权限读 /data/local/tmp）
            IRemoteProcess rp0 = svc0.newProcess(new String[]{"sh", "-c",
                    "cat " + src + " 2>/dev/null | tail -c 400000"}, null, "/");
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            java.io.InputStream ins = new android.os.ParcelFileDescriptor.AutoCloseInputStream(
                    rp0.getInputStream());
            byte[] buf = new byte[8192];
            int n;
            while ((n = ins.read(buf)) > 0) bo.write(buf, 0, n);
            ins.close();
            rp0.waitFor();

            String stamp = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss",
                    java.util.Locale.US).format(new java.util.Date());
            String name = "run-" + stamp + "-" + tag + ".txt";
            String rel = android.os.Environment.DIRECTORY_DOWNLOADS + "/山茶内核工坊/日志";

            StringBuilder head = new StringBuilder();
            head.append("# 山茶 · 内核工坊 运行日志\n")
                .append("# 版本 ").append(tag).append("\n")
                .append("# 时间 ").append(new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss",
                        java.util.Locale.US).format(new java.util.Date())).append("\n")
                .append("# ---- 链路输出 ----\n");
            byte[] body = bo.toByteArray();
            byte[] hb = head.toString().getBytes("UTF-8");

            if (android.os.Build.VERSION.SDK_INT >= 29) {
                // 2) 写入媒体库 Downloads（文件管理器/下载 App 立刻可见）
                android.content.ContentValues cv = new android.content.ContentValues();
                cv.put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, name);
                cv.put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "text/plain");
                cv.put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH, rel);
                android.net.Uri uri = getContentResolver().insert(
                        android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
                if (uri == null) return null;
                java.io.OutputStream os = getContentResolver().openOutputStream(uri);
                os.write(hb);
                os.write(body);
                os.flush();
                os.close();
                return "/sdcard/" + rel + "/" + name;
            }

            // 3) 旧系统：shell 直接写
            String dst = "/sdcard/" + rel + "/" + name;
            String cmd = "mkdir -p '/sdcard/" + rel + "'"
                    + "; { printf '%s' '" + head.toString().replace("'", "") + "'; cat " + src
                    + " 2>/dev/null; } > '" + dst + "'"
                    + "; am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d file://" + dst
                    + " >/dev/null 2>&1; ls '" + dst + "' >/dev/null 2>&1 && echo OK || echo FAIL";
            IRemoteProcess rp1 = svc0.newProcess(new String[]{"sh", "-c", cmd}, null, "/");
            java.io.BufferedReader r1 = new java.io.BufferedReader(
                    new java.io.InputStreamReader(
                            new android.os.ParcelFileDescriptor.AutoCloseInputStream(
                                    rp1.getInputStream())));
            String v = r1.readLine();
            rp1.waitFor();
            return (v != null && v.contains("OK")) ? dst : null;
        } catch (Throwable t) {
            return null;
        }
    }

    /** 导出诊断包（长按「保存」）：内核串 + 关键符号 + 最近日志，方便远程定位常量漂移。 */
    private void exportDiag() {
        new Thread(new Runnable() {
            public void run() {
                try {
                    if (!Shizuku.pingBinder()) { emit("诊断导出失败：Shizuku 未就绪", 0); return; }
                    IShizukuService svc0 = IShizukuService.Stub.asInterface(
                            new ShizukuBinderWrapper(Shizuku.getBinder()));
                    String stamp = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss",
                            java.util.Locale.US).format(new java.util.Date());
                    String name = "诊断-" + stamp + ".txt";
                    java.io.File f = new java.io.File(getCacheDir(), name);
                    StringBuilder sb = new StringBuilder();
                    sb.append("# 山茶诊断包\n");
                    sb.append("# 生成 ").append(stamp).append("\n");
                    sb.append("# App 版本 ").append(verChoice()).append("\n");
                    sb.append("# 内核 ").append(Payloads.uname()).append("\n\n");
                    sb.append("[符号地址]\n").append(shellText(svc0,
                            "grep -E ' (prepare_creds|do_timer_create|capable|load_module|trace_module_notify)$' /proc/kallsyms 2>/dev/null | head -20"));
                    sb.append("\n[kmem 事件]\n").append(shellText(svc0,
                            "cat /sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable 2>/dev/null; "
                          + "mkdir -p /sys/kernel/tracing 2>/dev/null; ls /sys/kernel/tracing/events/kmem 2>/dev/null | head"));
                    sb.append("\n[最近链路日志]\n").append(shellText(svc0,
                            "tail -c 120000 /data/local/tmp/cve-2026-98260.log 2>/dev/null; "
                          + "tail -c 80000 /data/local/tmp/own127.log 2>/dev/null"));
                    java.io.FileOutputStream fo = new java.io.FileOutputStream(f);
                    fo.write(sb.toString().getBytes("UTF-8"));
                    fo.close();

                    String rel = android.os.Environment.DIRECTORY_DOWNLOADS + "/山茶内核工坊/日志";
                    android.content.ContentValues cv = new android.content.ContentValues();
                    cv.put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, name);
                    cv.put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "text/plain");
                    cv.put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH, rel);
                    android.net.Uri u = getContentResolver().insert(
                            android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
                    if (u == null) { emit("诊断导出失败：无法写入下载目录", 0); return; }
                    java.io.OutputStream os = getContentResolver().openOutputStream(u);
                    java.io.FileInputStream fi = new java.io.FileInputStream(f);
                    byte[] b = new byte[8192]; int n;
                    while ((n = fi.read(b)) > 0) os.write(b, 0, n);
                    fi.close(); os.flush(); os.close();
                    emit("诊断包已保存 · /sdcard/" + rel + "/" + name, 1);
                } catch (Throwable t) {
                    emit("诊断导出异常：" + t.getClass().getSimpleName(), 0);
                }
            }
        }).start();
    }

    /** 以 shell 身份执行并取回文本（最多 64KB）。 */
    private String shellText(IShizukuService svc, String cmd) {
        try {
            IRemoteProcess rp = svc.newProcess(new String[]{"sh", "-c", cmd}, null, "/");
            java.io.InputStream in = new android.os.ParcelFileDescriptor.AutoCloseInputStream(
                    rp.getInputStream());
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] b = new byte[8192]; int n, total = 0;
            while ((n = in.read(b)) > 0 && total < 65536) { bo.write(b, 0, n); total += n; }
            in.close(); rp.waitFor();
            return bo.toString("UTF-8");
        } catch (Throwable t) {
            return "(读取失败: " + t.getClass().getSimpleName() + ")\n";
        }
    }

    /** 手动导出（长按「复制」）。 */
    private void exportLog() {
        new Thread(new Runnable() {
            public void run() {
                String p = saveLog(verChoice().isEmpty() ? "unknown" : verChoice());
                if (p != null) emit("日志已保存 · " + p, 1);
                else emit("日志保存失败（Shizuku 未就绪或目录不可写）", 0);
            }
        }).start();
    }

    /** 严格按 2.9 原版的启动与观察方式（逐字对齐其命令序列）。返回 false = 被 sha 门禁拦下。 */
    private boolean legacyStart(IShizukuService svc, String which, String wantSha) throws Exception {
        // 1) 环境准备 —— 与 2.9 逐字一致，一个字符都不加（含末尾的 ls -l）
        String prep = "mkdir -p /data/local/tmp"
                + "; [ -f /data/local/tmp/cve-2026-98260.log ] || : > /data/local/tmp/cve-2026-98260.log"
                + "; chmod 666 /data/local/tmp/cve-2026-98260.log 2>/dev/null"
                + "; chmod 777 /data/local/tmp 2>/dev/null"
                + "; chmod 755 /data/local/tmp/own127"
                + "; rm -f /data/local/tmp/.lock2 /data/local/tmp/own127.lock 2>/dev/null"
                + "; ls -l /data/local/tmp/cve-2026-98260.log /data/local/tmp/own127 2>&1";
        IRemoteProcess rp0 = svc.newProcess(new String[]{"sh", "-c", prep}, null, "/data/local/tmp");
        rp0.waitFor();
        emit("· 2.9 原版 prep 已执行（含 rm -f .lock2 / own127.lock），链路序列未改动", 0);

        /* 1.5) P1-2 载荷 sha 门禁 —— 独立一条命令，跑在 setsid 之前，不进启动链、
           不改启动链的 cwd/stdio/环境；不一致就根本不启动。 */
        String want = wantSha == null ? "" : wantSha.trim().toLowerCase(java.util.Locale.US);
        String wantShort = want.length() >= 12 ? want.substring(0, 12) + "…" : want;
        String gate = "cd /data/local/tmp"
                + "; H=$(sha256sum ./own127 2>/dev/null | cut -d' ' -f1 | tr 'A-Z' 'a-z')"
                + "; W=" + want
                + "; if [ -z \"$H\" ]; then echo \"GATE_FAIL got=none want=" + wantShort + "\"; exit 9; fi"
                + "; if [ \"$H\" != \"$W\" ]; then echo \"GATE_FAIL got=${H} want=" + wantShort + "\"; exit 9; fi"
                + "; echo \"GATE_OK sha=" + wantShort + "\"";
        IRemoteProcess rpg = svc.newProcess(new String[]{"sh", "-c", gate}, null, "/data/local/tmp");
        java.io.BufferedReader rg = new java.io.BufferedReader(new java.io.InputStreamReader(
                new android.os.ParcelFileDescriptor.AutoCloseInputStream(rpg.getInputStream())));
        String gv = rg.readLine();
        try { rg.close(); } catch (Throwable ignored) { }
        int grc = rpg.waitFor();
        if (gv == null || !gv.contains("GATE_OK") || grc != 0) {
            String got = gv == null ? "none" : gv.replace("GATE_FAIL ", "").trim();
            /* 只报给界面，不往 own127.log 或任何链路文件里写东西 */
            emit("· 载荷校验失败 · " + got + " · want=" + wantShort + " · 已阻止执行（exit 9），本轮不启动链路", 0);
            return false;
        }
        emit("· 载荷校验通过（7879）· sha=" + wantShort, 1);

        // 2) 起跑 —— 与 2.9 逐字一致
        String run = "cd /data/local/tmp"
                + "; rm -rf /data/local/tmp/chan"
                + "; mkdir -p /data/local/tmp/chan"
                + "; chmod 777 /data/local/tmp/chan"
                + "; rm -f /data/local/tmp/ksu_slide.txt"
                + "; setsid /data/local/tmp/own127 fake nofix > /data/local/tmp/own127.log 2>&1 < /dev/null &"
                + " echo started";
        IRemoteProcess rp1 = svc.newProcess(new String[]{"sh", "-c", run}, null, "/data/local/tmp");
        rp1.waitFor();
        emit("已按 2.9 原版方式启动（setsid 后台 · 日志 own127.log）", 1);

        // 3) 观察（2.9 用 wc -c 判增量；这里用 tail -c +偏移，等价且更省）
        long off = 0;
        long t0 = System.currentTimeMillis();
        /* 观察上限 300s（2.9 无明确上限，240s → 300s 只是放宽上限，不改间隔也不加提前退出） */
        while (System.currentTimeMillis() - t0 < 300000L) {
            try { Thread.sleep(800); } catch (InterruptedException ignored) { }
            IRemoteProcess rd = svc.newProcess(new String[]{"sh", "-c",
                    "wc -c < /data/local/tmp/own127.log 2>/dev/null"}, null, "/");
            java.io.BufferedReader rb = new java.io.BufferedReader(
                    new java.io.InputStreamReader(
                            new android.os.ParcelFileDescriptor.AutoCloseInputStream(rd.getInputStream())));
            String szs = rb.readLine();
            rb.close();
            rd.waitFor();
            long sz = 0;
            try { sz = Long.parseLong(szs == null ? "0" : szs.trim()); } catch (Throwable ignored) { }
            if (sz > off) {
                IRemoteProcess rc = svc.newProcess(new String[]{"sh", "-c",
                        "tail -c +" + (off + 1) + " /data/local/tmp/own127.log 2>/dev/null"}, null, "/");
                java.io.BufferedReader r2 = new java.io.BufferedReader(
                        new java.io.InputStreamReader(
                                new android.os.ParcelFileDescriptor.AutoCloseInputStream(rc.getInputStream())));
                String ln;
                while ((ln = r2.readLine()) != null) {
                    String l = ln.trim();
                    if (l.isEmpty()) continue;
                    lastLineAt = System.currentTimeMillis();
                    narrate(l);
                }
                r2.close();
                rc.waitFor();
                off = sz;
            }
            if (sawSuccess || parkedZombie) break;
        }
        emit("· 2.9 原版观察窗结束", 0);
        return true;
    }

    private String grab(String blob, String key) {
        for (String ln : blob.split("\n")) {
            String t = ln.trim();
            if (t.startsWith(key + "=")) return t.substring(key.length() + 1).trim();
        }
        return "?";
    }

    private boolean preflight(IShizukuService svc) {
        boolean ok = true;
        try {
            String info = shellText(svc,
                    "echo KM=$(cat /sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable 2>/dev/null);"
                  + " echo LOCK=$(ls /data/local/tmp/.lock2 /data/local/tmp/own127.lock 2>/dev/null | wc -l);"
                  + " echo PROC=$(pidof own127 | wc -w);"
                  + " echo MOD=$(grep -c kernelsu /proc/modules)");
            emit("· 预检 · kmem=" + grab(info, "KM") + " 残留锁=" + grab(info, "LOCK")
                    + " 旧进程=" + grab(info, "PROC") + " 模块=" + grab(info, "MOD"), 0);
            if (!"1".equals(grab(info, "KM")))
                emit("· 提示 · kmem 事件当前未开启（载荷运行时会自行开启，不影响启动）", 0);
            boolean hasLock = !"0".equals(grab(info, "LOCK"));
            boolean hasProc = !"0".equals(grab(info, "PROC"));
            boolean modLoaded = "1".equals(grab(info, "MOD"));
            if (hasLock || hasProc) {
                if (!modLoaded) {
                    shellText(svc, "rm -f /data/local/tmp/.lock2 /data/local/tmp/own127.lock 2>/dev/null; "
                            + "pkill -f own127 2>/dev/null; echo done");
                    emit("已自动清理上一轮残留（锁/进程）—— 上次是被重启打断的，属正常", 1);
                } else {
                    emit("⚠ 内核已接管且有残留进程，请先重启再跑", 0);
                    ok = false;
                }
            }
        } catch (Throwable ignored) { }
        return ok;
    }

    private void recoverLastRun() {
        new Thread(new Runnable() {
            public void run() {
                try { Thread.sleep(2600); } catch (InterruptedException ignored) { }
                try {
                    boolean pending = getSharedPreferences("ownctl", MODE_PRIVATE).getBoolean("run_pending", false);
                    if (!pending) return;
                    String ver = getSharedPreferences("ownctl", MODE_PRIVATE).getString("run_pending_ver", "unknown");
                    String renamed = finishSession("重启");
                    String p2 = saveLog(ver + "-重启前");
                    emit("上次运行因重启结束 · 已补存日志" + (renamed != null ? "（" + renamed + "）" : ""), 1);
                    getSharedPreferences("ownctl", MODE_PRIVATE).edit().putBoolean("run_pending", false).apply();
                } catch (Throwable ignored) { }
            }
        }).start();
    }

    /** 外层护栏：无论 startInner 在哪一步抛异常，running 都不会卡在 true。 */
    private void start() {
        if (running) { emit("§ 链路已在运行", 0); return; }
        try {
            startInner();
        } catch (Throwable t) {
            running = false;
            stopBreathe();
            emit("!! 启动失败 · 已复位运行标志：" + t, 0);
        }
    }

    private void startInner() {
        /* 7879 驻留状态落盘过：App 重启后仍然拦住（B 情形） */
        runLocked = loadRunLock();
        if (stateTaken) {
            emit("已接管 · 无需再启动（内核已打补丁，重复跑会 panic）", 0);
            return;
        }
        if (loadParked()) {
            parkedZombie = true;
            emit("上次老链路已驻留（持有页，状态已落盘）—— 请先重启设备，再开新一轮", 0);
            return;
        }
        if (runLocked) {
            emit("本次开机已启动过一轮 · 为防重复写入已锁定；要重开请点底部「重启手机」", 0);
            return;
        }
        long up = uptimeSec();
        long bid = bootId();                       /* 0 = 开机时长未知 */
        long lastBoot = getSharedPreferences("ownctl", MODE_PRIVATE).getLong("ran_boot", 0);
        boolean lastOk = getSharedPreferences("ownctl", MODE_PRIVATE)
                .getBoolean("ran_boot_ok", false);
        /* 门闩语义：同一次开机 + 已成功过 才拦；换了一次开机或上次没成功，一律放行重试 */
        if (bid != 0 && lastBoot == bid && lastOk) {
            long nowF = System.currentTimeMillis();
            if (nowF - forceRunAt > 3000) {
                forceRunAt = nowF;
                emit("本机这次开机已经成功接管过一次；再跑一轮风险很高（内核已打补丁）", 0);
                emit("—— 3 秒内再点一次「启动链路」可强行继续，否则请点「重启手机」重开窗口", 0);
                running = false;
                return;
            }
            emit("已确认强行再跑一轮（风险自负）", 0);
        }
        if (bid != 0 && lastBoot != bid) {
            /* 换了一次开机：上一次的 ok 不再代表这一次，先清零，成功时再置位 */
            getSharedPreferences("ownctl", MODE_PRIVATE).edit()
                    .putLong("ran_boot", bid)
                    .putBoolean("ran_boot_ok", false).apply();
        }
        if (verChoice().isEmpty()) {
            emit("请先在上方「链路版本」选择 3666 或 7879 —— 选错版本会在凭据阶段失败", 0);
            running = false;
            return;
        }
        if (parkedZombie) {
            emit("上次老链路已僵尸驻留（持有页）—— 请先重启设备，再开新一轮", 0);
            running = false;
            return;
        }
        {
            String relNow = Payloads.uname();
            String vcNow = verChoice();
            boolean fit = (vcNow.equals("3666")
                        && (relNow.contains("573773666") || relNow.contains("gd489d4ad2a70")))
                       || (vcNow.equals("7879")
                        && (relNow.contains("7879") || relNow.contains("567717946")));
            if (!fit)
                emit("⚠ 当前内核与所选版本不一致：内核 " + relNow + " · 已选 " + vcNow
                        + " —— 已放行，继续按你的选择执行", 0);
        }
        if (up < 0) {
            /* 开机时长读不到：显示“未知”，不打印 -1，也不拦链路 */
            emit("开机时长未知 · 窗口状态未知；若本轮失败，请点底部「重启手机」后立刻重试", 0);
        } else if (up > 150) {
            long nowL = System.currentTimeMillis();
            if (nowL - lateArmedAt > 3000) {
                lateArmedAt = nowL;
                emit("⚠ 本次开机已 " + up + " 秒，远超有效窗口（90 秒内）——这一轮几乎必然失败", 0);
                emit("—— 3 秒内再点一次「启动链路」仍要强行尝试，否则请点「重启手机」", 0);
                running = false;
                return;
            }
            emit("已确认在超窗状态下强行尝试（失败风险高）", 0);
        } else if (up > 90) {
            emit("⚠ 本次开机已 " + up + " 秒，利用窗口通常只在开机 90 秒内有效", 0);
            emit("⚠ 建议先点底部「重启手机」，开机后立刻再启动", 0);
        } else {
            emit("开机 " + up + " 秒 · 窗口有效", 1);
        }
        boolean shizukuOk = Shizuku.pingBinder()
                && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
        boolean suOk = hasSu();
        if (!shizukuOk && !suOk) { sayShizukuState(); return; }
        emit(shizukuOk ? "身份：Shizuku shell" : "身份：su（回退通道）", 0);
        if (shizukuOk) {
            try {
                IShizukuService svcPre = IShizukuService.Stub.asInterface(
                        new ShizukuBinderWrapper(Shizuku.getBinder()));
                if (!preflight(svcPre)) {
                    long nowP = System.currentTimeMillis();
                    if (nowP - preWarnAt > 3000) {
                        preWarnAt = nowP;
                        emit("—— 3 秒内再点一次「启动链路」可在警告状态下强行继续，否则请先重启设备", 0);
                        running = false;
                        return;
                    }
                    emit("已确认在警告状态下强行继续", 0);
                }
            } catch (Throwable ignored) { }
        }
        /* ---- 从这里开始「已开跑」，任何一步失败都必须把 running 退回去 ---- */
        try {
            running = true;
            /* 点过启动就锁死按钮（落盘，按开机 id 生效）：本次开机不再允许第二轮 */
            saveRunLock();
            startLocked = true;
            lockStartButton("已启动");
            /* 每轮门闩全量复位：上一轮的 true 残留会让本轮完全静默（P0-2） */
            runEnded = false;
            runReader = null;
            runStream = null;
            sawSuccess = false;
            successDeclared = false;
            tailDropped = 0;
            watchStop = false;
            shownStage = 0;
            parkedZombie = false;
            stateTaken = false;
            lastLineAt = System.currentTimeMillis();
            synchronized (liveBuf) { liveBuf.setLength(0); }
            liveWritten = 0;
            liveHeader = false;
            lastLiveFlush = 0;
            startSession();
            getSharedPreferences("ownctl", MODE_PRIVATE).edit().putInt("attempt", 0).apply();
            for (int i = 0; i < 6; i++) if (pills[i] != null)
                pills[i].setBackgroundResource(R.drawable.pill_off);
            stageIdx = 0;
            progress.setText("进度 0 / 6");
            badge.setText("运行中");
            stage.setText("准备 · 释放链路文件");
            startBreathe();
            new Thread(new Runnable() {
                public void run() {
                    try {
                        if (Shizuku.pingBinder()
                                && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED)
                            runViaShizuku();
                        else
                            runViaSu();
                    } catch (Throwable e) {
                        emit("!! 启动异常：" + e, 0);
                    } finally {
                        /* 统一出口：任何异常路径都不许把 running 留在 true */
                        running = false;
                        stopBreathe();
                        if (!sawSuccess && !successDeclared) {
                            markBootResult(false);
                            ui.post(new Runnable() { public void run() {
                                try {
                                    badge.setText("已停止");
                                    badge.setBackgroundResource(R.drawable.pill_off);
                                    badge.setTextColor(0xFF7387A0);
                                } catch (Throwable ignored) { }
                            }});
                        }
                    }
                }
            }).start();
        } catch (Throwable t) {
            running = false;
            stopBreathe();
            emit("!! 启动失败 · 已复位运行标志：" + t, 0);
        }
    }

    private void runViaShizuku() throws Exception {
        String rel = Payloads.uname();
        String[] bound = boundPayload();
        if (bound == null) {
            emit("未选择链路版本 · 请先在上方选择 3666 或 7879", 0);
            return;
        }
        String which = bound[0];
        String wantSha = bound[1];
        emit("内核 " + rel, 0);
        emit("链路版本 " + verChoice() + " → 内置资产 " + which
                + "（" + bound[2] + " B · sha " + wantSha.substring(0, 12) + "…）", 1);

        File ko = new File(getFilesDir(), "kernelsu_patched.ko");
        unpack("kernelsu_patched.ko", ko);

        // 内置链路位在 nativeLibraryDir，Shizuku 以 shell 身份可直接执行
        File newBin = new File(getApplicationInfo().nativeLibraryDir, "libown128.so");
        File oldBin = new File(getApplicationInfo().nativeLibraryDir, "libown128p.so");
        File bin = which.equals("own127") ? newBin : oldBin;
        if (!bin.exists()) { bin = new File(getFilesDir(), "own128"); unpack(which, bin); }
        emit("链路位 " + bin.getName() + " · 资产 " + which, 0);
        emit("模块镜像 " + ko.length() + " 字节", 0);

        // shell 读不到 app 私有目录，必须用 Shizuku 进程的 stdin 灌进 /data/local/tmp
        svc = IShizukuService.Stub.asInterface(new ShizukuBinderWrapper(Shizuku.getBinder()));
        svcRef = svc;
        /* 只比字节数会漏判：527672 与 527672 完全可能是两支不同的载荷。旧版就因此
           一直“跳过灌注”，实际跑的是 /data/local/tmp 里那份陈旧文件，换了打包的
           载荷也不生效。现在按 尺寸+md5 判断是否真的已就位。 */
        if ("7879".equals(verChoice()) || !sameRemote(svc, "/data/local/tmp/own127", which)) {
            pushAsset(svc, which, "/data/local/tmp/own127", "755");
            emit("链路载荷已写入（7879 强制覆盖，与 2.9 的 cp -f 一致）", 0);
        } else {
            emit("链路已就位 · 跳过灌注", 0);
        }
        if (!sameRemote(svc, "/data/local/tmp/kernelsu_patched.ko", "kernelsu_patched.ko"))
            pushAsset(svc, "kernelsu_patched.ko", "/data/local/tmp/kernelsu_patched.ko", "644");
        else
            emit("模块镜像已就位 · 跳过灌注", 0);

        /* 与手工可用形态逐字一致：cd 进目录、重建 chan、清两个残留文件、直接跑载荷。
           不再追加 2>&1 / 前置探针命令 / 不同 cwd —— 这些都会改变载荷看到的 stdio 与
           fd 布局，而手工成功时跑的就是下面这一条。 */
        if ("7879".equals(verChoice())) {
            getSharedPreferences("ownctl", MODE_PRIVATE).edit()
                    .putBoolean("run_pending", true)
                    .putString("run_pending_ver", verChoice()).apply();
            /* 2.9 会检查 KernelSU 管理器是否存在/版本；这里只提示，不自动安装 */
            String ksu = ksuManagerInfo();
            emit(ksu != null
                    ? "· 提示 · KernelSU 管理器 " + ksu
                    : "· 提示 · 未检测到 KernelSU 管理器（me.weishu.kernelsu）—— 接管成功后请自行安装，本 App 不代装", 0);
            emit("以 shell 身份启动链路（2.9 原版方式 · nofix）", 0);
            boolean gateOk = legacyStart(svc, which, wantSha);
            getSharedPreferences("ownctl", MODE_PRIVATE).edit()
                    .putBoolean("run_pending", false).apply();
            /* P1-1：7879 以前从不 finalize，日志永远停在「进行中」 */
            if (sawSuccess && !successDeclared) declareSuccess();
            markBootResult(sawSuccess);
            String outcome = !gateOk ? "失败-载荷校验"
                    : (sawSuccess ? "成功" : (parkedZombie ? "驻留" : "失败"));
            /* A 成功 / B 驻留：不杀进程，只收尾；C 真失败：SIGTERM→复核→SIGKILL 彻底清理 */
            endRun(outcome, "7879", gateOk ? 0 : 9,
                    gateOk && !sawSuccess && !parkedZombie);
            if ("驻留".equals(outcome))
                emit("· 老链路已驻留 · 请重启设备；本状态已落盘，App 重启后仍会拦住启动", 0);
            return;
        }
        String cmd = "cd /data/local/tmp && rm -rf chan && mkdir -p chan"
                + " && chmod 777 chan && rm -f .lock2 ksu_slide.txt"
                + " && H=$(sha256sum ./own127 2>/dev/null | cut -d' ' -f1 | tr 'A-Z' 'a-z')"
                + " && W=" + wantSha.toLowerCase(java.util.Locale.US) + " && if [ \"$H\" != \"$W\" ]; then"
                + " echo \"· 载荷校验失败 · got=${H:-none} want=" + wantSha.substring(0, 12) + "… · 已阻止执行\"; exit 9; fi"
                + " && echo \"· 载荷校验通过 · sha=" + wantSha.substring(0, 12) + "… · 版本 " + verChoice() + "\""
                + " && ./own127 fake nofix";

        getSharedPreferences("ownctl", MODE_PRIVATE).edit()
                .putBoolean("run_pending", true)
                .putString("run_pending_ver", verChoice()).apply();
        emit("以 shell 身份启动链路（nofix）", 0);
        rp = svc.newProcess(new String[]{"sh", "-c", cmd}, null, "/data/local/tmp");
        drainErr(rp);
        InputStream is = new android.os.ParcelFileDescriptor.AutoCloseInputStream(
                rp.getInputStream());
        lastLineAt = System.currentTimeMillis();
        final IRemoteProcess rpWatch = rp;
        new Thread(new Runnable() {
            public void run() {
                while (true) {
                    try { Thread.sleep(5000); } catch (InterruptedException ignored) { return; }
                    if (watchStop) return;
                    if (sawSuccess) return;          // 已成功：进入保活，绝不能杀
                    long idle = System.currentTimeMillis() - lastLineAt;
                    if (idle > 45000) {
                        emit("· 卡住 · 已 " + (idle / 1000) + " 秒无输出 —— 清理本次链路进程", 0);
                        try { rpWatch.destroy(); } catch (Throwable ignored) { }
                        /* 未成功 = 还没拿到页，此时杀是安全的（成功路径上面已 return）。
                           用 PID 精确清理，不用 pkill -f（会自匹配到本进程的 sh -c）。 */
                        try { killChainIfSafe(); } catch (Throwable ignored) { }
                        return;
                    }
                }
            }
        }).start();
        runStream = is;
        runReader = new BufferedReader(new InputStreamReader(is));
        final java.io.BufferedReader rr = runReader;
        String line;
        while ((line = rr.readLine()) != null) {
            lastLineAt = System.currentTimeMillis();
            narrate(line);
        }
        /* 成功/驻留路径上 declareSuccess 已经收过尾（runEnded=true），这里只补没结束的情况 */
        int rc = -1;
        if (!runEnded) {
            watchStop = true;
            try { rc = rp.waitFor(); } catch (Throwable ignored) { }
            emit("· 收尾 · 链路进程已退出（code=" + rc + "）", 0);
        } else {
            emit("· 读句柄已由收尾关闭（成功/驻留路径）", 0);
        }
        getSharedPreferences("ownctl", MODE_PRIVATE).edit()
                .putBoolean("run_pending", false).apply();
        if (sawSuccess && !successDeclared) declareSuccess();
        else if (!runEnded) emit("· 结束 · 本次未接管内核", 0);
        markBootResult(sawSuccess);
        /* 3666 也走统一收尾：成功不杀（pause 保活），失败/超时才清理进程 */
        String outcome3666 = sawSuccess ? "成功" : (parkedZombie ? "驻留" : ("失败-code" + rc));
        endRun(outcome3666, verChoice().isEmpty() ? "unknown" : verChoice(), rc,
                !sawSuccess && !parkedZombie);
        emit("§ 链路退出 code=" + rc, 0);
        boolean live = sawSuccess || stateTaken;
        for (int i = 0; i < 20 && !live; i++) {
            live = moduleLoaded();
            if (!live) try { Thread.sleep(500); } catch (InterruptedException ignored) { }
        }
        if (live) {
            advance("完成");
            emit("内核已接管 · 正在切到 KernelSU", 1);
            openKsu();
        } else {
            emit("本轮未接管 · 建议重启再来", 0);
        }
        ui.post(new Runnable() {
            public void run() {
                if (stageIdx < 7) {
                    badge.setText("已停止");
                    badge.setBackgroundResource(R.drawable.pill_off);
                    badge.setTextColor(0xFF7387A0);
                }
            }
        });
    }

    /**
     * 后台抽干 stderr。
     *
     * 手工跑时 stderr 和 stdout 落在同一个终端上，所以那些 [!]/RDFAIL 行看得见；
     * 这里不改载荷的 fd 1（不合并），只把 stderr 的内容单独读进来补进日志 ——
     * 顺带避免 stderr 管道写满把链路卡住。
     */
    private void drainErr(final IRemoteProcess p) {
        try {
            final InputStream es = new android.os.ParcelFileDescriptor.AutoCloseInputStream(
                    p.getErrorStream());
            new Thread(new Runnable() {
                public void run() {
                    try {
                        BufferedReader r = new BufferedReader(new InputStreamReader(es));
                        String l;
                        while ((l = r.readLine()) != null) if (!l.trim().isEmpty()) narrate(l);
                    } catch (Throwable ignored) { }
                }
            }).start();
        } catch (Throwable ignored) { }
    }

    private boolean hasSu() {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "su -c id"});
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            String line = r.readLine();
            p.waitFor();
            return line != null && line.contains("uid=0");
        } catch (Throwable t) {
            return false;
        }
    }

    private void runViaSu() throws Exception {
        String rel = Payloads.uname();
        String[] bound = boundPayload();
        if (bound == null) { emit("未选择链路版本 · 请先在上方选择 3666 或 7879", 0); return; }
        String[] pick = new String[] { bound[0], "用户选定 " + verChoice() };
        File ko = new File(getFilesDir(), "kernelsu_patched.ko");
        unpack("kernelsu_patched.ko", ko);
        File bin = new File(getApplicationInfo().nativeLibraryDir,
                pick[0].equals("own127") ? "libown128.so" : "libown128p.so");
        if (!bin.exists()) { bin = new File(getFilesDir(), "own128"); unpack(pick[0], bin); }
        emit("内核 " + rel + " · 链路 " + pick[0] + "（" + pick[1] + "）", 0);

        String inner = "rm -f /data/local/tmp/own128; cp " + bin + " /data/local/tmp/own128; chmod 755 /data/local/tmp/own128; "
                + "rm -f /data/local/tmp/kernelsu_patched.ko; cp " + ko + " /data/local/tmp/kernelsu_patched.ko; "
                + "chmod 644 /data/local/tmp/kernelsu_patched.ko; chmod 777 /data/local/tmp; "
                + "rm -f /data/local/tmp/.lock2 /data/local/tmp/ksu_slide.txt; "
                + "cd /data/local/tmp; ./own128 fake nofix";
        String outer = "su -c \"" + inner + "\" 2>&1";
        emit("以 su 身份启动链路（nofix）", 0);
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", outer});
        java.io.BufferedReader r = new java.io.BufferedReader(
                new java.io.InputStreamReader(p.getInputStream()));
        String line;
        while ((line = r.readLine()) != null) narrate(line);
        int rc = p.waitFor();
        emit("§ 链路退出 code=" + rc, 0);
        /* su 回退路径同样要收尾，否则又留一个「进行中」（P1-1 同类问题） */
        markBootResult(false);
        String fin = finishSession("失败-su" + rc);
        emit(fin != null ? "本轮日志文件 · " + fin : "本轮日志改名失败", fin != null ? 1 : 0);
    }

    private void unpack(String asset, File dst) throws Exception {
        if (dst.exists() && dst.length() > 0) { dst.setExecutable(true, false); return; }
        InputStream in = getAssets().open(asset);
        OutputStream out = new FileOutputStream(dst);
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        out.close(); in.close();
        dst.setExecutable(true, false);
    }

    /* ================= 统一收尾（两条链路都走这里） ================= */
    private final Object runLock = new Object();
    /** 本轮是否已经收尾（幂等闸门，防止 declareSuccess 与读线程各收一次）. */
    private volatile boolean runEnded;
    /** 本轮持有的本地流与读句柄：收尾时必须关掉，否则 fd 泄漏。 */
    private volatile java.io.BufferedReader runReader;
    private volatile InputStream runStream;

    /** 只关本地 fd 与读句柄；绝不 destroy 远端进程（成功/驻留时 destroy 会杀掉持有页的载荷）。 */
    private void closeLocalStreams() {
        try { if (runReader != null) runReader.close(); } catch (Throwable ignored) { }
        runReader = null;
        try { if (runStream != null) runStream.close(); } catch (Throwable ignored) { }
        runStream = null;
    }

    private void shQuiet(String cmd) {
        try {
            IShizukuService s = svcRef;
            if (s == null) {
                if (!Shizuku.pingBinder()) return;
                s = IShizukuService.Stub.asInterface(new ShizukuBinderWrapper(Shizuku.getBinder()));
            }
            IRemoteProcess p = s.newProcess(new String[]{"sh", "-c", cmd}, null, "/");
            p.waitFor();
        } catch (Throwable ignored) { }
    }

    /** pidof own127 的原始输出（可能多 pid，空串=没有）。 */
    private String remotePids() {
        try {
            IShizukuService s = svcRef;
            if (s == null) {
                if (!Shizuku.pingBinder()) return "";
                s = IShizukuService.Stub.asInterface(new ShizukuBinderWrapper(Shizuku.getBinder()));
            }
            IRemoteProcess p = s.newProcess(new String[]{"sh", "-c",
                    "pidof own127 2>/dev/null || echo"}, null, "/");
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(
                    new android.os.ParcelFileDescriptor.AutoCloseInputStream(p.getInputStream())));
            String v = r.readLine();
            r.close();
            p.waitFor();
            return v == null ? "" : v.trim();
        } catch (Throwable t) { return ""; }
    }

    /**
     * 失败路径清理：pidof own127 取真实 PID → kill -TERM → 1.5s 复核 → 仍在则 kill -9。
     * 用 PID 而不是 `pkill -f`：pkill 的 -f 会匹配到执行它的那条 sh -c（自匹配），
     * 信号还没发完就把自己打断，复核也就拿不到真实结果；PID 精确、不自伤。
     * 成功 / 驻留 / 内核已接管 一律拒绝（此时载荷持有页，杀掉会 UAF）。
     */
    private boolean killChainIfSafe() {
        if (sawSuccess || successDeclared || parkedZombie) {
            emit("· 已成功/已驻留 · 拒绝清理进程（杀了会引起 UAF）", 0);
            return false;
        }
        boolean mod = false;
        try { mod = moduleLoaded(); } catch (Throwable ignored) { }
        if (mod) { emit("· 内核已接管 · 拒绝清理进程", 0); return false; }
        String pids = remotePids();
        if (pids == null || pids.isEmpty()) {
            emit("· 清理复核：pidof own127 为空（本轮没有留下进程）", 1);
            return true;
        }
        /* 1) SIGTERM，精确到 pid */
        shQuiet("kill -TERM " + pids + " 2>/dev/null; true");
        try { Thread.sleep(1500); } catch (InterruptedException ignored) { }
        String alive = remotePids();
        /* 2) 复核：还在就 SIGKILL */
        if (alive != null && !alive.isEmpty()) {
            emit("· 清理复核：仍有 pid " + alive + " · 补发 SIGKILL", 0);
            shQuiet("kill -9 " + alive + " 2>/dev/null; true");
            try { Thread.sleep(800); } catch (InterruptedException ignored) { }
            alive = remotePids();
        }
        boolean clean = alive == null || alive.isEmpty();
        emit(clean ? "· 进程已清理（pidof own127 为空）"
                   : "· 进程仍在：" + alive + "（已两次发信号）", clean ? 1 : 0);
        return clean;
    }

    /**
     * 唯一收尾入口：关流 → 停看门狗 →（失败才清理进程）→ 复位 running → 命名会话 → 保存日志。
     * outcome 取 "成功" / "驻留" / "失败…"；killIfFailed=false 时绝不动进程。
     */
    /** 2.9 的兜底成功判据：grep -i kernelsu /proc/modules 有输出即视为接管成功。 */
    private boolean legacyFallbackOk() {
        try {
            if (!Shizuku.pingBinder()) return moduleLoaded();
            IShizukuService svc0 = IShizukuService.Stub.asInterface(
                    new ShizukuBinderWrapper(Shizuku.getBinder()));
            String out = shellText(svc0, "grep -ic kernelsu /proc/modules 2>/dev/null");
            return out != null && !out.trim().isEmpty() && !"0".equals(out.trim());
        } catch (Throwable t) {
            return moduleLoaded();
        }
    }

    private void endRun(String outcome, String logTag, int rc, boolean killIfFailed) {
        // 2.9 兜底：日志没抓到 SUCCESS、但 /proc/modules 已有 kernelsu → 仍按成功收尾
        if ("7879".equals(verChoice()) && !sawSuccess && legacyFallbackOk()) {
            sawSuccess = true;
            legacyFailed = false;
            emit("· 2.9 兜底判据命中 · /proc/modules 里已有 kernelsu", 1);
            if ("失败".equals(outcome)) outcome = "成功";
            killIfFailed = false;
        }
        synchronized (runLock) {
            if (runEnded) return;
            runEnded = true;
        }
        closeLocalStreams();                 /* 1) 关流（只关本地 fd） */
        watchStop = true;                    /* 2) 停看门狗 */
        boolean clean = true;
        if (killIfFailed) clean = killChainIfSafe();   /* 3) 失败才清理 */
        running = false;                     /* 4) 复位运行态 */
        stopBreathe();
        String fin = finishSession(outcome); /* 5) 命名会话 */
        String sp = saveLog(logTag);         /* 6) 保存日志 */
        if ("驻留".equals(outcome)) saveParked(true);
        final String finF = fin, spF = sp;
        final boolean cleanF = clean;
        ui.post(new Runnable() {
            public void run() {
                try {
                    if (stateTaken || successDeclared || sawSuccess) {
                        applyUiTaken("已接管 · 已驻留保活，无需再启动");
                    } else {
                        badge.setText("已结束");
                        badge.setBackgroundResource(R.drawable.pill_off);
                        badge.setTextColor(0xFF7387A0);
                        progress.setText("进度 0 / 6");
                        lockStartButton("已启动过");
                    }
                } catch (Throwable ignored) { }
                if (finF != null) emit("本轮日志文件 · " + finF, 1);
                else emit("本轮日志改名失败", 0);
                if (spF != null) emit("日志已保存 · " + spF, 1);
            }
        });
        /* 7) 一行结论 */
        if ("成功".equals(outcome))
            emit("· 收尾完成 · 已驻留勿杀（pause，CPU≈0 / RSS<1MB）—— 要重开窗口请重启设备", 1);
        else if ("驻留".equals(outcome))
            emit("· 收尾完成 · 老链路已驻留，请重启设备；本状态已落盘，App 重启后仍会拦住启动", 0);
        else
            emit("本轮已结束 · " + (killIfFailed
                    ? (clean ? "进程已清理 · 可重启后再试" : "进程未能清理 · 请重启设备")
                    : "无需清理 · 可重启后再试"), killIfFailed && clean ? 1 : 0);
    }

    /** 驻留状态落盘：重启 App 后仍拦住「启动链路」；换了一次开机自动失效。 */
    private void saveParked(boolean parked) {
        try {
            long bid = bootId();
            getSharedPreferences("ownctl", MODE_PRIVATE).edit()
                    .putBoolean("parked", parked)
                    .putLong("parked_boot", bid).apply();
        } catch (Throwable ignored) { }
    }

    private boolean loadParked() {
        try {
            long bid = bootId();
            if (bid == 0) return false;
            return getSharedPreferences("ownctl", MODE_PRIVATE).getBoolean("parked", false)
                    && getSharedPreferences("ownctl", MODE_PRIVATE).getLong("parked_boot", 0) == bid;
        } catch (Throwable t) { return false; }
    }

    /** 用户直接划掉 App（onDestroy）时兜底：仍在跑且未成功 → 按失败路径清理。 */
    private void cleanupOnLeave() {
        if (!running || runEnded) return;
        if (sawSuccess || successDeclared || parkedZombie) return;
        new Thread(new Runnable() {
            public void run() {
                try {
                    boolean mod = moduleLoaded();
                    if (mod) { running = false; return; }   /* 已接管：绝不动进程 */
                    endRun("失败-离开界面", verChoice(), -1, true);
                } catch (Throwable ignored) { }
            }
        }).start();
    }

    private void stop() {
        boolean killed = false;
        try {
            if (rp != null) { rp.destroy(); killed = true; }
        } catch (Exception ignored) { }
        watchStop = true;              /* 3666 的看门狗线程读这个标志 */
        if (killed) emit("已中止链路 · 进程已回收", 0);
        else if ("7879".equals(verChoice()))
            /* 按硬约束：7879 的观察循环不改行为（不加提前退出），这里只说事实，不假称已回收 */
            emit("已标记中止 · 7879 走 setsid、无进程句柄可回收；观察按 2.9 原版继续到上限，内核写路径不受影响", 0);
        else emit("已中止 · 没有可回收的进程句柄", 0);
        running = false;
        stopBreathe();
        /* 跑过就还是锁着的：本次开机不允许再点第二轮 */
        startLocked = true;
        if (!stateTaken) {
            ui.post(new Runnable() { public void run() {
                try {
                    badge.setText("已停止");
                    badge.setBackgroundResource(R.drawable.pill_off);
                    badge.setTextColor(0xFF7387A0);
                    lockStartButton("已启动过");
                } catch (Throwable ignored) { }
            }});
        }
    }
}