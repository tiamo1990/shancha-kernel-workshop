package com.shancha.ownctl;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * 按内核版本挑链路二进制。
 *
 * 两支载荷各对应一代内核，必须都在包里、运行时按 uname -r 选：
 *   - 17.2.14.x/15.x（构建号后缀 573773666 / 3666）→ own127      （自有载荷）
 *   - 老一代（构建号后缀 7879 / 567717946）        → own127_prev （历史载荷, EA7801…，v2.9 成功过那支）
 * 拿错代际必然卡在 cred（offset 对不上），所以这里先用构建号精确匹配，再按代际回落。
 */
final class Payloads {

    /** 内核特征串 → 链路资产名。顺序有意义：先精确构建号，再宽泛特征。 */
    private static final String[][] MAP = {
            // 新内核：17.2.14.x / 17.2.15.x（gd489d4ad2a70，cred 站点 0xe5770）
            {"573773666", "own127"},
            {"gd489d4ad2a70", "own127"},
            // 老内核：17.2.11.x 及更早（v2.9 那一代成功过的链路）
            {"7879", "own127_prev"},
            {"567717946", "own127_prev"},
    };

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

    /** 返回 {资产名, 选择理由}。 */
    static String[] pick(String release) {
        if (release == null || release.isEmpty())
            return new String[] { "own127", "内核版本读不到，优先用新内核链路" };
        for (String[] row : MAP)
            if (release.contains(row[0]))
                return new String[] { row[1], "命中内核特征 " + row[0] };
        // 没命中具体构建号：按代际回落，新链路优先
        if (release.contains("6.6.12") || release.compareTo("6.6.120") >= 0)
            return new String[] { "own127", "按代际回落（6.6.12x 及以上）→ 新内核链路" };
        return new String[] { "own127_prev", "按代际回落到老内核链路" };
    }
}
