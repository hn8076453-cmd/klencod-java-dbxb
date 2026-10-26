package shshsb.sbsbsbdb;

import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HCDecryptor {

    // ---------- أدوات مساعدة ----------

    private static String cleanHex(String raw) {
        if (raw == null) return "";
        String c = raw.replaceAll("[^0-9a-fA-F]", "");
        return (c.length() % 2 != 0) ? "0" + c : c;
    }

    private static boolean isHex(String s) {
        return s != null && s.length() >= 16 && s.matches("^[0-9a-fA-F]+$");
    }

    private static boolean isMostlyPrintable(String s, boolean strict) {
        if (s == null || s.isEmpty()) return false;
        if (s.length() < 4) return true;
        int printable = 0;
        for (char c : s.toCharArray()) {
            if (c >= 32 && c < 127) printable++;
        }
        return ((double) printable / s.length()) > (strict ? 0.90 : 0.80);
    }

    // ---------- z3a (أرقام عشرية) ----------

    private static String extractZ3a(String data, int iv) {
        if (data == null || data.isEmpty()) return "";
        List<Byte> bytes = new ArrayList<>();
        Pattern p = Pattern.compile("(-?\\d+)\\.(-?\\d+)");
        Matcher m = p.matcher(data);
        while (m.find()) {
            try {
                int v11 = Integer.parseInt(m.group(1)) - iv;
                int v22 = Integer.parseInt(m.group(2)) - iv;
                long div = 1L << v22;
                if (div != 0) {
                    bytes.add((byte) ((v11 / div) % 256));
                }
            } catch (Exception ignored) {}
        }
        byte[] arr = new byte[bytes.size()];
        for (int i = 0; i < arr.length; i++) arr[i] = bytes.get(i);
        try { return new String(arr, "UTF-8"); } catch (Exception e) { return ""; }
    }

    // ---------- Braille ----------

    private static String decryptBraille(String text) {
        try {
            byte[] out = new byte[text.length() / 2];
            for (int i = 0; i + 1 < text.length(); i += 2) {
                int a = HCConstants.BRAILLE_ALPHABET.indexOf(text.charAt(i));
                int b = HCConstants.BRAILLE_ALPHABET.indexOf(text.charAt(i + 1));
                out[i / 2] = (byte) (((a * 16) + b) & 255);
            }
            return new String(out, "UTF-8");
        } catch (Exception e) {
            return text;
        }
    }

    // ---------- معالجة بيانات الاعتماد ----------

    private static String processCredentials(String raw, boolean isSsh) {
        if (raw == null || raw.isEmpty()) return raw;

        if (isSsh && HCConstants.BRAILLE_ALPHABET.indexOf(raw.charAt(0)) >= 0) {
            raw = decryptBraille(raw);
        }

        Pattern p = isSsh
            ? Pattern.compile("^([\\w\\.-]+):([\\d-]+)@(.+):(.+)$")
            : Pattern.compile("^([^:]+):(.+)$");

        Matcher m = p.matcher(raw);
        if (m.matches()) {
            String[] g;
            if (isSsh) {
                g = new String[]{ m.group(1), m.group(2), m.group(3), m.group(4) };
            } else {
                g = new String[]{ m.group(1), m.group(2) };
            }
            String uEnc = g[g.length - 2];
            String pEnc = g[g.length - 1];

            int uIv = countMatches(uEnc, "(-?\\d+)\\.(-?\\d+)");
            int pIv = countMatches(pEnc, "(-?\\d+)\\.(-?\\d+)");

            String uDec = extractZ3a(uEnc, uIv);
            String pDec = extractZ3a(pEnc, pIv);

            String fu = uDec.isEmpty() ? uEnc : uDec;
            String fp = pDec.isEmpty() ? pEnc : pDec;

            if (isSsh) {
                return g[0] + ":" + g[1] + "@" + fu + ":" + fp;
            } else {
                return fu + ":" + fp;
            }
        }
        return raw;
    }

    private static int countMatches(String s, String regex) {
        Matcher m = Pattern.compile(regex).matcher(s);
        int c = 0;
        while (m.find()) c++;
        return c;
    }

    // ---------- abc / ChaCha20 ----------

    public static String abcDecrypt(String raw, byte[] key, byte[] nonce) {
        if (raw == null || raw.isEmpty()) return "";
        try {
            byte[] data = HCConstants.hexToBytes(cleanHex(raw));
            if (data.length > 16) {
                byte[] ct = new byte[data.length - 16];
                System.arraycopy(data, 0, ct, 0, ct.length);
                byte[] pt = CryptoUtils.chacha20Decrypt(key, nonce, ct);
                if (pt != null) return new String(pt, "UTF-8");
            }
        } catch (Exception ignored) {}
        return "";
    }

    // ---------- rst (XOR + AES) ----------

    public static String rstDecrypt(String enc) {
        try {
            byte[] input = enc.getBytes("UTF-8");
            byte[] xored = new byte[input.length];
            for (int i = 0; i < input.length; i++) {
                xored[i] = (byte) (input[i] ^ HCConstants.RST_XOR_KEY[i % 20]);
            }
            byte[] aesCt = android.util.Base64.decode(xored, android.util.Base64.DEFAULT);

            for (byte[] key : HCConstants.RST_KEYS) {
                byte[] pt = CryptoUtils.aesEcbDecrypt(key, aesCt);
                if (pt != null) {
                    String s = new String(pt, "UTF-8");
                    if (s.contains("[splitConfig]")) return s;
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    // ---------- jkl (Base64 + XOR معكوس) ----------

    public static String jklDecrypt(String input, boolean isNew) {
        if (input == null || input.isEmpty()) return input;
        try {
            int pad = input.length() % 4;
            String padded = pad != 0 ? input + "====".substring(pad) : input;
            byte[] data = android.util.Base64.decode(padded, android.util.Base64.DEFAULT);
            byte[] key = isNew ? HCConstants.JKL_KEY_NEW : HCConstants.JKL_KEY_OLD;

            byte[] mixed = new byte[data.length];
            for (int i = 0; i < data.length; i++) {
                int d = data[i] & 0xff;
                int k = key[i % 20] & 0xff;
                mixed[i] = (byte) ((((d ^ 0xff) & 0xca) | (d & 0x35))
                                 ^ (((k ^ 0xff) & 0xca) | (k & 0x35)));
            }
            byte[] decoded = android.util.Base64.decode(mixed, android.util.Base64.DEFAULT);
            return new String(decoded, "UTF-8");
        } catch (Exception e) {
            return input;
        }
    }

    // ---------- فك تشفير حقل فردي ----------

    private static String decryptField(String token, byte[] dynamicNonce) {
        if (token == null || token.isEmpty()) return token;
        if (token.equals("true") || token.equals("false")
            || token.equals("lifeTime")
            || token.equals("[splitPsiphon][splitPsiphon]")
            || token.startsWith("<")) {
            return token;
        }

        List<byte[]> candidates = new ArrayList<>();
        String ch = cleanHex(token);
        if (isHex(ch) && ch.length() >= 32) {
            try { candidates.add(HCConstants.hexToBytes(ch)); } catch (Exception ignored) {}
        }
        if (token.length() > 16) {
            try { candidates.add(token.getBytes("ISO-8859-1")); } catch (Exception ignored) {}
            try { candidates.add(token.getBytes("UTF-8")); } catch (Exception ignored) {}
        }

        // إزالة التكرار
        List<byte[]> unique = new ArrayList<>();
        for (byte[] c : candidates) {
            boolean dup = false;
            for (byte[] u : unique) if (java.util.Arrays.equals(u, c)) { dup = true; break; }
            if (!dup) unique.add(c);
        }

        for (byte[] dataBytes : unique) {
            if (dataBytes.length <= 16) continue;
            byte[] ct = new byte[dataBytes.length - 16];
            System.arraycopy(dataBytes, 0, ct, 0, ct.length);

            for (byte[] key : HCConstants.CHACHA_KEYS) {
                byte[] pt = CryptoUtils.chacha20Decrypt(key, dynamicNonce, ct);
                if (pt == null) continue;
                String decStr = new String(pt, java.nio.charset.StandardCharsets.UTF_8);

                for (boolean isNew : new boolean[]{true, false}) {
                    String out = jklDecrypt(decStr, isNew);
                    if (!out.equals(decStr) && isMostlyPrintable(out, false)) return out;
                }

                if (isMostlyPrintable(decStr, true) &&
                    (decStr.contains("HTTP") || decStr.contains("@") || decStr.contains(":")
                     || decStr.contains("{") || decStr.matches("^[A-Za-z0-9]+$"))) {
                    return decStr;
                }
            }
        }

        for (boolean isNew : new boolean[]{true, false}) {
            String out = jklDecrypt(token, isNew);
            if (!out.equals(token) && isMostlyPrintable(out, false)) return out;
        }

        return token;
    }

    // ---------- فك تشفير الحمولة الأولية ----------

    private static String extractInitialPayload(byte[] fileBytes, byte[] keyBytes) {
        try {
            byte[] out = new byte[fileBytes.length];
            for (int i = 0; i < fileBytes.length; i++) {
                out[i] = (byte) (fileBytes[i] ^ keyBytes[i % keyBytes.length]);
            }
            return new String(out, "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }

    // ---------- الدالة الرئيسية ----------

    public static String execute(byte[] fileBytes) {
        try {
            byte[] initialKey = HCConstants.hexToBytes("e382e4b8adc386f09f9293");
            String hexPayload = extractInitialPayload(fileBytes, initialKey);
            if (hexPayload == null) return error("فشل استخراج الحمولة الأولية");

            String outer = abcDecrypt(hexPayload, HCConstants.CHACHA_KEYS[5], HCConstants.STATIC_NONCE);
            if (outer == null || !outer.startsWith("{")) return error("فشل فك التشفير الخارجي");

            JSONObject json = new JSONObject(outer);
            JSONObject cfg = json.optJSONObject("cfg");
            boolean isNewFormat = cfg != null && cfg.has("content");

            Map<String, String> meta = new LinkedHashMap<>();
            Map<String, String> protections = new LinkedHashMap<>();

            String targetCipher;
            String splitDelim;

            if (isNewFormat) {
                addIfPresent(meta, protections, "hwid", json.optString("b", cfg.optString("b", "")));
                addIfPresent(meta, protections, "area", json.optString("f", cfg.optString("f", "")));
                targetCipher = cfg.optString("content", "");
                splitDelim = "[splitConfig]";
            } else {
                JSONObject objA = json.optJSONObject("a");
                if (objA == null) objA = new JSONObject();
                addIfPresent(meta, protections, "hwid",
                    objA.optString("bb", ""));
                String pwd = json.optString("e", "");
                if (!pwd.isEmpty()) {
                    String dec = abcDecrypt(pwd, HCConstants.CHACHA_KEYS[7], HCConstants.STATIC_NONCE);
                    if (!dec.isEmpty()) { meta.put("password", dec); protections.put("password", dec); }
                }
                addIfPresent(meta, protections, "area", objA.optString("fe", ""));
                String prov = objA.optString("ed", "");
                if (!prov.isEmpty()) {
                    String dec = abcDecrypt(prov, HCConstants.CHACHA_KEYS[7], HCConstants.STATIC_NONCE);
                    if (!dec.isEmpty()) { meta.put("provider", dec); protections.put("provider", dec); }
                }
                targetCipher = !json.optString("xy", "").isEmpty() ? json.optString("xy") : objA.optString("xy", "");
                splitDelim = !json.optString("uv", "").isEmpty() ? json.optString("uv") : objA.optString("uv", "");
            }

            if (targetCipher.isEmpty() || splitDelim.isEmpty()) return error("لا يوجد محتوى مشفر");

            String h = meta.get("hwid");
            String p = meta.get("password");
            String pr = meta.get("provider");
            String a = meta.get("area");

            String derivedHex;
            if (h != null && !h.isEmpty() && p == null && pr == null && a == null) {
                derivedHex = toHex(h) + toHex(h);
            } else {
                derivedHex = toHex(p) + toHex(h) + toHex(pr) + toHex(a);
            }

            byte[] dynamicNonce = HCConstants.STATIC_NONCE.clone();
            if (!derivedHex.isEmpty()) {
                try {
                    byte[] dh = HCConstants.hexToBytes(derivedHex);
                    for (int i = 0; i < Math.min(8, dh.length); i++) dynamicNonce[i] = dh[i];
                } catch (Exception ignored) {}
            }

            String xyDec;
            if (isNewFormat) {
                xyDec = rstDecrypt(targetCipher);
                if (xyDec == null) {
                    for (byte[] k : HCConstants.CHACHA_KEYS) {
                        String t = abcDecrypt(targetCipher, k, HCConstants.STATIC_NONCE);
                        if (t != null && t.contains(splitDelim)) { xyDec = t; break; }
                    }
                }
            } else {
                xyDec = abcDecrypt(targetCipher, HCConstants.CHACHA_KEYS[1], HCConstants.STATIC_NONCE);
            }

            if (xyDec == null) return error("فشل فك تشفير المحتوى الرئيسي");

            String[] tokens = xyDec.split(Pattern.quote(splitDelim), -1);
            Map<String, Object> configData = new LinkedHashMap<>();

            for (int i = 0; i < tokens.length; i++) {
                if (i == 22 || i == 24) continue;
                String label = HCConstants.TOKEN_MAP.containsKey(i)
                    ? HCConstants.TOKEN_MAP.get(i) : ("field_" + i);
                String token = tokens[i];
                String finalOut = token;

                if (isNewFormat) {
                    finalOut = decryptField(token, dynamicNonce);
                } else {
                    if (isHex(token)) {
                        finalOut = abcDecrypt(token, HCConstants.CHACHA_KEYS[7], dynamicNonce);
                    }
                    finalOut = jklDecrypt(finalOut, false);
                }

                if (i == 7) finalOut = processCredentials(finalOut, true);
                else if (i == 11) finalOut = processCredentials(finalOut, false);

                if (finalOut != null && !finalOut.isEmpty()) {
                    finalOut = finalOut.replace(
                        "88a05e8772eac3e5703e0cd26c6e6f23de72fb09f7ee5a43283d1681f19d", "");
                    if (finalOut.startsWith("{") || finalOut.startsWith("[")) {
                        try {
                            configData.put(label, new JSONObject(finalOut));
                            continue;
                        } catch (Exception ignored) {}
                    }
                    if (!isHex(finalOut)) configData.put(label, finalOut);
                }
            }

            JSONObject result = new JSONObject();
            result.put("Protections", new JSONObject(protections));
            result.put("Config", new JSONObject(configData));
            return result.toString(4);

        } catch (Exception e) {
            return error(e.getMessage());
        }
    }

    private static void addIfPresent(Map<String, String> meta, Map<String, String> prot, String key, String val) {
        if (val != null && !val.isEmpty()) { meta.put(key, val); prot.put(key, val); }
    }

    private static String toHex(String s) {
        if (s == null || s.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static String error(String msg) {
        return "❌ فشل فك التشفير: " + msg;
    }
}