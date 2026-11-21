package com.shancha.ownctl;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * 按内核版本挑选链路载荷。
 *
 * 原则：**永不阻断**。精确命中就用对应那一支；没命中就按内核代际回落，
 * 仍然继续尝试（只是把"未精确匹配"的提示打给用户）。
 */
final class Payloads {

    /** 内核特征 -> 资产名。顺序有意义：先精确构建号，再宽泛特征。 */
    private static final String[][] MAP = {
            // 新内核：17.2.14.x / 17.2.15.x（gd489d4ad2a70，cred 站点 0xe5770）
            {"573773666", "own127"},
            {"gd489d4ad2a70", "own127"},
            // 老内核：17.2.11.x 及更早（v2.9 那一代成功过的链路）
            {"7879", "own127_prev"},
            {"567717946", "own127_prev"},
    };

    /** 读 assets/payloads.json：{id,asset,size,sha256,label,kernel}；失败返回 null。 */
    static java.util.List<String[]> loadManifest(android.content.Context c) {
        java.util.List<String[]> out = new java.util.ArrayList<>();
        try {
            java.io.InputStream is = c.getAssets().open("payloads.json");
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = is.read(buf)) > 0) bo.write(buf, 0, n);
            is.close();
            org.json.JSONObject root = new org.json.JSONObject(bo.toString("UTF-8"));
            org.json.JSONArray arr = root.getJSONArray("payloads");
            for (int i = 0; i < arr.length(); i++) {
                org.json.JSONObject o = arr.getJSONObject(i);
                out.add(new String[] {
                        o.getString("id"), o.getString("asset"),
                        String.valueOf(o.optLong("size")),
                        o.getString("sha256"),
                        o.optString("label", o.getString("id")),
                        o.optString("kernel", "") });
            }
        } catch (Throwable t) {
            return null;
        }
        return out.isEmpty() ? null : out;
    }

    static String uname() {
        try {
            Process p = new ProcessBuilder("/system/bin/uname", "-r")
                    .redirectErrorStream(true).start();
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String v = r.readLine();
            p.waitFor();
            return v == null ? "" : v.trim();
        } catch (Exception e) {
            return "";
        }
    }

    /** 返回 {资产名, 理由, 是否精确命中("1"/"0")}。 */
    static String[] pick(String release) {
        if (release == null || release.isEmpty())
            return new String[] { "own127", "内核版本读不到 · 按新内核链路尝试", "0" };
        for (String[] row : MAP)
            if (release.contains(row[0]))
                return new String[] { row[1], "命中内核特征 " + row[0], "1" };
        if (release.contains("6.6.12") || release.compareTo("6.6.120") >= 0)
            return new String[] { "own127", "未精确匹配 · 按代际回落到新内核链路", "0" };
        return new String[] { "own127_prev", "未精确匹配 · 按代际回落到老内核链路", "0" };
    }
}
