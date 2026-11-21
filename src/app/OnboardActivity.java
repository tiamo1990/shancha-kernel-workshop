package com.shancha.ownctl;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

/**
 * 首次运行：无线调试授权。
 *
 * 链路要以 shell 身份执行，应用沙箱做不到。这里提供与系统无线调试的授权入口：
 * 打开设置页 → 用户读出配对端口与配对码 → 回到本页填入 → 建立授权。
 */
public class OnboardActivity extends Activity {

    private EditText port, code;
    private TextView state;
    private SharedPreferences sp;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_onboard);
        sp = getSharedPreferences("ownctl", MODE_PRIVATE);
        port = findViewById(R.id.port);
        code = findViewById(R.id.code);
        state = findViewById(R.id.state);

        findViewById(R.id.openSettings).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { openWirelessSettings(); }
        });
        findViewById(R.id.pair).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { pair(); }
        });

        port.setText(sp.getString("pair_port", ""));
        if (sp.getBoolean("paired", false)) {
            state.setText("状态：已授权 · 端口 " + sp.getString("pair_port", "?"));
        }
    }

    private void openWirelessSettings() {
        // 无线调试在部分机型没有独立入口，逐级回退
        String[] actions = {
                "android.settings.WIRELESS_DEBUGGING_SETTINGS",
                Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS
        };
        for (String a : actions) {
            try {
                startActivity(new Intent(a));
                return;
            } catch (Exception ignored) { }
        }
        try {
            startActivity(new Intent(Settings.ACTION_SETTINGS));
        } catch (Exception e) {
            state.setText("状态：无法打开设置，请手动进入开发者选项");
        }
    }

    private void pair() {
        final String p = port.getText().toString().trim();
        final String c = code.getText().toString().trim();
        if (p.isEmpty() || c.length() != 6) {
            state.setText("状态：请填写配对端口与 6 位配对码");
            return;
        }
        state.setText("状态：正在建立授权…");
        new Thread(new Runnable() {
            public void run() {
                // 第一段：确认端口可达（配对握手由 AdbPair 实现，见下一版）
                boolean ok = AdbPair.reachable("127.0.0.1", Integer.parseInt(p));
                final boolean f = ok;
                runOnUiThread(new Runnable() {
                    public void run() {
                        if (f) {
                            sp.edit().putString("pair_port", p).putBoolean("paired", true).apply();
                            state.setText("状态：端口可达，授权记录已保存。点击返回开始链路。");
                            findViewById(R.id.pair).postDelayed(new Runnable() {
                                public void run() {
                                    startActivity(new Intent(OnboardActivity.this, MainActivity.class));
                                    finish();
                                }
                            }, 900);
                        } else {
                            state.setText("状态：端口不可达，请确认无线调试已打开并核对端口");
                        }
                    }
                });
            }
        }).start();
    }
}