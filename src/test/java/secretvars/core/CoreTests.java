package secretvars.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/** Pruebas del núcleo sin dependencias (ejecutar con: java secretvars.core.CoreTests). */
public final class CoreTests
{
    private static int passed;
    private static final List<String> failures = new ArrayList<>();

    public static void main(String[] args)
    {
        Map<String, String> vals = new HashMap<>();
        vals.put("token", "eyJhbGciOiJIUzI1NiJ9.payload.sig");
        vals.put("user", "admin");
        vals.put("pass", "p@ss w\"rd/ñ");
        vals.put("empty", "");
        Function<String, String> lookup = vals::get;

        // --- motor
        Substitution s = PlaceholderEngine.substitute("Authorization: Bearer {{secret:token}}", lookup, true);
        eq("bearer", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig", s.output());
        eq("count", 1, s.replacements());

        s = PlaceholderEngine.substitute("{{secret:user}}:{{secret:user}}", lookup, true);
        eq("repetido", "admin:admin", s.output());
        eq("repetido count", 2, s.replacements());
        eq("used dedupe", 1, s.used().size());

        s = PlaceholderEngine.substitute("x={{secret:nope}}&y={{secret:user}}", lookup, true);
        eq("missing literal", "x={{secret:nope}}&y=admin", s.output());
        truth("missing reported", s.missing().contains("nope"));

        s = PlaceholderEngine.substitute("{{secret:empty}}|", lookup, true);
        eq("empty value", "|", s.output());

        s = PlaceholderEngine.substitute("{{7*7}} {{ secret:user }} {{secret:}}", lookup, true);
        eq("no SSTI collision", "{{7*7}} {{ secret:user }} {{secret:}}", s.output());
        eq("no SSTI count", 0, s.replacements());

        String b64 = Base64.getEncoder().encodeToString("admin".getBytes());
        s = PlaceholderEngine.substitute("Basic {{secret:user|b64}}", lookup, true);
        eq("b64", "Basic " + b64, s.output());

        s = PlaceholderEngine.substitute("{{secret:pass|url}}", lookup, true);
        eq("url utf8", "p%40ss%20w%22rd%2F%C3%B1", s.output());

        s = PlaceholderEngine.substitute("{\"p\":\"{{secret:pass|json}}\"}", lookup, true);
        // salida en cadena de bytes: ñ como UTF-8 (2 bytes)
        eq("json", "{\"p\":\"p@ss w\\\"rd/ñ\"}",
                new String(Bytes.fromLatin1(s.output()), StandardCharsets.UTF_8));

        s = PlaceholderEngine.substitute("{{secret:user|hex}}", lookup, true);
        eq("hex", "61646d696e", s.output());

        s = PlaceholderEngine.substitute("{{secret:user|b64|url}}", lookup, true);
        eq("chain", "YWRtaW4%3D", s.output());

        s = PlaceholderEngine.substitute("{{secret:user|b64url}}", lookup, true);
        eq("b64url", "YWRtaW4", s.output());

        s = PlaceholderEngine.substitute("{{secret:user|rot13}}", lookup, true);
        eq("bad modifier literal", "{{secret:user|rot13}}", s.output());
        truth("bad modifier reported", !s.errors().isEmpty());

        s = PlaceholderEngine.substitute("{{secret:user|b64}}", n -> "****", false);
        eq("masked ignores modifiers", "****", s.output());

        s = PlaceholderEngine.substitute("{{secret:pass}}", lookup, true);
        eq("utf8 bytes", "p@ss w\"rd/ñ", new String(Bytes.fromLatin1(s.output()), StandardCharsets.UTF_8));

        // --- HTTP/1
        String req = "POST /api?k={{secret:user}} HTTP/1.1\r\n"
                + "Host: example.com\r\n"
                + "Authorization: Bearer {{secret:token}}\r\n"
                + "Content-Type: application/json\r\n"
                + "Content-Length: 25\r\n"
                + "\r\n"
                + "{\"pwd\":\"{{secret:pass}}\"}";
        byte[] raw = req.getBytes(StandardCharsets.ISO_8859_1);
        int bodyOffset = req.indexOf("\r\n\r\n") + 4;
        eq("fixture CL", 25, raw.length - bodyOffset);

        Http1Rewriter.Result r = Http1Rewriter.rewrite(raw, bodyOffset, lookup, true);
        String outStr = new String(r.bytes(), StandardCharsets.ISO_8859_1);
        int newBodyOffset = outStr.indexOf("\r\n\r\n") + 4;
        int newBodyLen = r.bytes().length - newBodyOffset;
        truth("http1 path", outStr.startsWith("POST /api?k=admin HTTP/1.1\r\n"));
        truth("http1 header", outStr.contains("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig\r\n"));
        truth("http1 CL updated flag", r.contentLengthUpdated());
        truth("http1 CL value", outStr.contains("Content-Length: " + newBodyLen + "\r\n"));
        eq("http1 counts", 3, r.stats().replacements());

        // Content-Length deliberadamente incorrecto: no se toca
        String req2 = req.replace("Content-Length: 25", "Content-Length: 5");
        r = Http1Rewriter.rewrite(req2.getBytes(StandardCharsets.ISO_8859_1), bodyOffset - 1, lookup, true);
        outStr = new String(r.bytes(), StandardCharsets.ISO_8859_1);
        truth("manual CL preserved", outStr.contains("Content-Length: 5\r\n"));
        truth("manual CL warning", !r.warnings().isEmpty());

        // Sustitución solo en cabeceras: el cuerpo y Content-Length intactos
        String req3 = "GET / HTTP/1.1\r\nHost: x\r\nX-Key: {{secret:user}}\r\nContent-Length: 4\r\n\r\nbody";
        r = Http1Rewriter.rewrite(req3.getBytes(StandardCharsets.ISO_8859_1), req3.indexOf("\r\n\r\n") + 4, lookup, true);
        eq("header-only", "GET / HTTP/1.1\r\nHost: x\r\nX-Key: admin\r\nContent-Length: 4\r\n\r\nbody",
                new String(r.bytes(), StandardCharsets.ISO_8859_1));

        // Sin marcadores: misma instancia de bytes
        byte[] plain = "GET / HTTP/1.1\r\nHost: x\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
        r = Http1Rewriter.rewrite(plain, plain.length, lookup, true);
        truth("no-op same bytes", r.bytes() == plain && !r.changed());

        // Bytes no ASCII fuera de los marcadores se conservan
        byte[] binary = new byte[]{'P', 'O', 'S', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1', '\r', '\n',
                '\r', '\n', (byte) 0xff, (byte) 0x00, (byte) 0x80};
        byte[] withPh = Bytes.splice(binary, binary.length, binary.length,
                "{{secret:user}}".getBytes(StandardCharsets.ISO_8859_1));
        r = Http1Rewriter.rewrite(withPh, 19, lookup, true);
        byte[] expected = Bytes.splice(binary, binary.length, binary.length, "admin".getBytes(StandardCharsets.ISO_8859_1));
        truth("binary preserved", java.util.Arrays.equals(expected, r.bytes()));

        // Chunked: aviso
        String req4 = "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n{{secret:user}}\r\n0\r\n\r\n";
        r = Http1Rewriter.rewrite(req4.getBytes(StandardCharsets.ISO_8859_1), req4.indexOf("\r\n\r\n") + 4, lookup, true);
        truth("chunked warning", r.warnings().stream().anyMatch(w -> w.contains("chunked")));

        // bodyOffset inválido -> fallback
        r = Http1Rewriter.rewrite(req3.getBytes(StandardCharsets.ISO_8859_1), -1, lookup, true);
        truth("fallback offset", new String(r.bytes(), StandardCharsets.ISO_8859_1).contains("X-Key: admin"));

        // --- almacén
        Map<Scope, String> storage = new EnumMap<>(Scope.class);
        Map<Scope, SecretStore.Backend> backends = new EnumMap<>(Scope.class);
        for (Scope sc : Scope.values())
        {
            backends.put(sc, new SecretStore.Backend()
            {
                public String load()
                {
                    return storage.get(sc);
                }

                public void save(String data)
                {
                    storage.put(sc, data);
                }
            });
        }
        SecretStore store = new SecretStore(backends);
        store.load();
        int[] events = {0};
        store.addListener(() -> events[0]++);

        store.upsert(null, new Secret("apikey", "GLOBAL-VALUE", Scope.GLOBAL, "clave"));
        eq("global lookup", "GLOBAL-VALUE", store.lookup("apikey"));
        store.upsert(null, new Secret("apikey", "PROJECT-VALUE", Scope.PROJECT, ""));
        eq("project overrides", "PROJECT-VALUE", store.lookup("apikey"));
        Secret g = store.find(Scope.GLOBAL, "apikey").orElseThrow();
        truth("global shadowed", store.isShadowed(g));

        threw("duplicate rejected", () -> store.upsert(null, new Secret("apikey", "x", Scope.PROJECT, "")));
        threw("bad name rejected", () -> store.upsert(null, new Secret("bad name", "x", Scope.PROJECT, "")));

        Secret p = store.find(Scope.PROJECT, "apikey").orElseThrow();
        store.upsert(p, p.withValue("ROTATED"));
        eq("rotated", "ROTATED", store.lookup("apikey"));

        store.remove(store.find(Scope.PROJECT, "apikey").orElseThrow());
        eq("fallback to global", "GLOBAL-VALUE", store.lookup("apikey"));
        eq("events fired", 4, events[0]); // 2 altas, 1 cambio, 1 baja (los rechazos no notifican)

        // Valores con ':' , saltos de línea y unicode sobreviven a la serialización
        store.upsert(null, new Secret("weird", "a:b\nc\r\n✓", Scope.PROJECT, "d:e"));
        SecretStore reloaded = new SecretStore(backends);
        reloaded.load();
        eq("roundtrip value", "a:b\nc\r\n✓", reloaded.lookup("weird"));
        eq("roundtrip desc", "d:e", reloaded.find(Scope.PROJECT, "weird").orElseThrow().description());
        eq("roundtrip global", "GLOBAL-VALUE", reloaded.lookup("apikey"));

        // Cambiar de ámbito persiste en ambos
        Secret w = reloaded.find(Scope.PROJECT, "weird").orElseThrow();
        reloaded.upsert(w, new Secret("weird", w.value(), Scope.GLOBAL, w.description()));
        SecretStore again = new SecretStore(backends);
        again.load();
        truth("scope move", again.find(Scope.PROJECT, "weird").isEmpty() && again.find(Scope.GLOBAL, "weird").isPresent());

        // Uso
        store.recordUse(List.of("apikey", "apikey"));
        eq("usage", 2L, store.usage("apikey").count());
        truth("usage dirty", store.consumeUsageDirty() && !store.consumeUsageDirty());

        // Secret.toString no filtra el valor
        truth("toString masks", !new Secret("n", "TOPSECRET", Scope.PROJECT, "").toString().contains("TOPSECRET"));

        System.out.println("OK: " + passed + "  FALLOS: " + failures.size());
        failures.forEach(f -> System.out.println("  - " + f));
        if (!failures.isEmpty())
        {
            System.exit(1);
        }
    }

    private static void eq(String name, Object expected, Object actual)
    {
        if (expected.equals(actual))
        {
            passed++;
        }
        else
        {
            failures.add(name + ": esperado <" + expected + "> obtenido <" + actual + ">");
        }
    }

    private static void truth(String name, boolean cond)
    {
        if (cond)
        {
            passed++;
        }
        else
        {
            failures.add(name);
        }
    }

    private static void threw(String name, Runnable r)
    {
        try
        {
            r.run();
            failures.add(name + ": no lanzó excepción");
        }
        catch (IllegalArgumentException e)
        {
            passed++;
        }
    }
}
