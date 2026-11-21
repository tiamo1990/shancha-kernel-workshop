package com.shancha.ownctl;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

/** 收到开机广播后拉起链路服务。 */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context ctx, Intent intent) {
        if (!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) return;
        // 默认不自动跑：一次开机只留一次机会给用户手点，避免自动那轮把窗口/kprobe 用掉
        if (!ctx.getSharedPreferences("ownctl", Context.MODE_PRIVATE)
                .getBoolean("auto_run", false)) return;
        Intent s = new Intent(ctx, ChainService.class);
        if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(s);
        else ctx.startService(s);
    }
}