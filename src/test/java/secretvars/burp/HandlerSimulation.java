package secretvars.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Preferences;
import secretvars.core.Scope;
import secretvars.core.Secret;
import secretvars.core.SecretStore;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Simulación del flujo real de Burp para el HttpHandler, con una implementación mínima de la API
 * Montoya mediante proxies dinámicos (Burp no está disponible fuera de Burp).
 *
 * Reproduce el caso de uso: una pestaña de Repeater con marcadores se envía, se cambia el valor
 * del secreto y se vuelve a enviar la MISMA pestaña.
 */
public final class HandlerSimulation
{
    private static int passed;
    private static final List<String> failures = new ArrayList<>();
    private static final List<String> logs = new ArrayList<>();

    public static void main(String[] args)
    {
        installFactory();

        Map<String, Object> prefsData = new HashMap<>();
        Settings settings = new Settings(preferences(prefsData));
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

                public void save(String d)
                {
                    storage.put(sc, d);
                }
            });
        }
        SecretStore store = new SecretStore(backends);
        store.load();
        store.upsert(null, new Secret("jwt", "AAA.BBB.CCC", Scope.PROJECT, ""));
        store.upsert(null, new Secret("password", "S3cr3t!", Scope.GLOBAL, ""));

        SecretsHttpHandler handler = new SecretsHttpHandler(api(), store, settings);

        // --- Pestaña de Repeater (HTTP/1.1)
        String tab = "POST /login?debug={{secret:password|url}} HTTP/1.1\r\n"
                + "Host: target.local\r\n"
                + "Authorization: Bearer {{secret:jwt}}\r\n"
                + "Content-Type: application/json\r\n"
                + "Content-Length: 41\r\n"
                + "\r\n"
                + "{\"user\":\"admin\",\"pass\":\"{{secret:password}}\"}";
        tab = tab.replace("Content-Length: 41", "Content-Length: " + (tab.length() - tab.indexOf("\r\n\r\n") - 4));
        byte[] tabBytes = tab.getBytes(StandardCharsets.ISO_8859_1);
        FakeRequest repeaterTab = new FakeRequest(tabBytes, ToolType.REPEATER);

        String sent1 = send(handler, repeaterTab);
        truth("envío 1: Authorization", sent1.contains("Authorization: Bearer AAA.BBB.CCC\r\n"));
        truth("envío 1: query url-encoded", sent1.startsWith("POST /login?debug=S3cr3t%21 HTTP/1.1"));
        truth("envío 1: cuerpo", sent1.endsWith("{\"user\":\"admin\",\"pass\":\"S3cr3t!\"}"));
        truth("envío 1: Content-Length", sent1.contains("Content-Length: " + bodyLen(sent1) + "\r\n"));
        truth("pestaña intacta tras envío 1", new String(repeaterTab.raw, StandardCharsets.ISO_8859_1).equals(tab));

        // --- Se rota el token (p. ej. desde la pestaña SecretVars o el menú contextual)
        Secret jwt = store.find(Scope.PROJECT, "jwt").orElseThrow();
        store.upsert(jwt, jwt.withValue("NEW.TOKEN.VALUE-mas-largo"));

        String sent2 = send(handler, repeaterTab);
        truth("envío 2: usa el valor nuevo", sent2.contains("Authorization: Bearer NEW.TOKEN.VALUE-mas-largo\r\n"));
        truth("envío 2: sin valor antiguo", !sent2.contains("AAA.BBB.CCC"));
        truth("pestaña intacta tras envío 2", new String(repeaterTab.raw, StandardCharsets.ISO_8859_1).equals(tab));
        eq("contador de usos jwt", 2L, store.usage("jwt").count());

        // --- Sin marcadores: misma instancia, sin coste
        FakeRequest plain = new FakeRequest("GET / HTTP/1.1\r\nHost: x\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1), ToolType.PROXY);
        truth("sin marcadores: misma instancia", handler.handleHttpRequestToBeSent(plain.self).request() == plain.self);

        // --- Herramienta desactivada
        settings.setToolEnabled(ToolType.REPEATER, false);
        truth("Repeater desactivado: sin sustituir", send(handler, repeaterTab).contains("{{secret:jwt}}"));
        settings.setToolEnabled(ToolType.REPEATER, true);
        FakeRequest intruder = new FakeRequest(tabBytes, ToolType.INTRUDER);
        truth("Intruder activo", send(handler, intruder).contains("NEW.TOKEN.VALUE-mas-largo"));

        // --- Interruptor general
        settings.setEnabled(false);
        truth("extensión desactivada", send(handler, repeaterTab).contains("{{secret:jwt}}"));
        settings.setEnabled(true);

        // --- Variable no definida: literal + un único aviso
        logs.clear();
        FakeRequest missing = new FakeRequest(
                "GET /?a={{secret:nope}} HTTP/1.1\r\nHost: x\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1), ToolType.REPEATER);
        truth("no definida: literal", send(handler, missing).contains("{{secret:nope}}"));
        send(handler, missing);
        eq("no definida: un solo aviso", 1L, logs.stream().filter(l -> l.contains("'nope'")).count());

        // --- Los logs nunca contienen valores
        settings.setLogSubstitutions(true);
        send(handler, repeaterTab);
        truth("logs sin valores", logs.stream().noneMatch(l -> l.contains("NEW.TOKEN") || l.contains("S3cr3t")));
        truth("log de sustitución con nombres", logs.stream().anyMatch(l -> l.contains("jwt") && l.contains("password")));

        // --- HTTP/2 con cabeceras únicas (withUpdatedHeader)
        FakeRequest h2 = new FakeRequest(("GET /api/{{secret:password}} HTTP/2\r\nHost: x\r\n"
                + "Authorization: Bearer {{secret:jwt}}\r\nAccept: */*\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1),
                ToolType.REPEATER);
        RequestToBeSentAction a = handler.handleHttpRequestToBeSent(h2.self);
        FakeRequest h2out = unwrap(a.request());
        truth("h2: versión conservada", "HTTP/2".equals(h2out.httpVersion()));
        truth("h2: ruta", h2out.path().equals("/api/S3cr3t!"));
        truth("h2: cabecera", h2out.str().contains("Authorization: Bearer NEW.TOKEN.VALUE-mas-largo\r\n"));
        truth("h2: orden de cabeceras", h2out.str().indexOf("Authorization") < h2out.str().indexOf("Accept"));

        // --- HTTP/2 con cabeceras duplicadas (reconstrucción ordenada)
        FakeRequest h2dup = new FakeRequest(("POST /x HTTP/2\r\nHost: x\r\ncookie: a=1\r\ncookie: s={{secret:jwt}}\r\n"
                + "content-length: 17\r\n\r\npw={{secret:password}}").getBytes(StandardCharsets.ISO_8859_1), ToolType.REPEATER);
        FakeRequest dupOut = unwrap(handler.handleHttpRequestToBeSent(h2dup.self).request());
        String d = dupOut.str();
        truth("h2 dup: ambas cookies en orden", d.indexOf("cookie: a=1\r\n") >= 0
                && d.indexOf("cookie: a=1") < d.indexOf("cookie: s=NEW.TOKEN.VALUE-mas-largo"));
        truth("h2 dup: cuerpo", d.endsWith("pw=S3cr3t!"));

        System.out.println("OK: " + passed + "  FALLOS: " + failures.size());
        failures.forEach(f -> System.out.println("  - " + f));
        if (!failures.isEmpty())
        {
            System.exit(1);
        }
    }

    private static String send(SecretsHttpHandler h, FakeRequest r)
    {
        return unwrap(h.handleHttpRequestToBeSent(r.self).request()).str();
    }

    private static int bodyLen(String s)
    {
        return s.length() - s.indexOf("\r\n\r\n") - 4;
    }

    // =================================================================== API simulada

    private static final HttpService SERVICE = proxy(HttpService.class, (name, args) -> switch (name)
    {
        case "host" -> "target.local";
        case "port" -> 443;
        case "secure" -> true;
        default -> null;
    });

    private static final Annotations ANNOTATIONS = proxy(Annotations.class, (n, a) -> null);

    /** HttpRequestToBeSent mínimo respaldado por los bytes en bruto. */
    static final class FakeRequest
    {
        final byte[] raw;
        final ToolType tool;
        final HttpRequestToBeSent self;

        FakeRequest(byte[] raw, ToolType tool)
        {
            this.raw = raw;
            this.tool = tool;
            this.self = (HttpRequestToBeSent) Proxy.newProxyInstance(HandlerSimulation.class.getClassLoader(),
                    new Class<?>[]{HttpRequestToBeSent.class, Unwrap.class}, (p, m, args) -> dispatch(m.getName(), args));
        }

        String str()
        {
            return new String(raw, StandardCharsets.ISO_8859_1);
        }

        int bodyOffset()
        {
            int i = str().indexOf("\r\n\r\n");
            return i < 0 ? raw.length : i + 4;
        }

        String requestLine()
        {
            return str().substring(0, str().indexOf("\r\n"));
        }

        String httpVersion()
        {
            String[] p = requestLine().split(" ");
            return p[p.length - 1];
        }

        String path()
        {
            return requestLine().split(" ")[1];
        }

        List<String[]> headerPairs()
        {
            List<String[]> out = new ArrayList<>();
            String head = str().substring(0, bodyOffset() - 4);
            String[] lines = head.split("\r\n");
            for (int i = 1; i < lines.length; i++)
            {
                int c = lines[i].indexOf(':');
                out.add(new String[]{lines[i].substring(0, c), lines[i].substring(c + 1).trim()});
            }
            return out;
        }

        String body()
        {
            return str().substring(bodyOffset());
        }

        FakeRequest rebuild(String path, List<String[]> headers, String body, boolean fixLength)
        {
            String[] rl = requestLine().split(" ");
            StringBuilder sb = new StringBuilder(rl[0] + " " + path + " " + rl[2] + "\r\n");
            for (String[] h : headers)
            {
                String v = fixLength && h[0].equalsIgnoreCase("content-length") ? Integer.toString(body.length()) : h[1];
                sb.append(h[0]).append(": ").append(v).append("\r\n");
            }
            sb.append("\r\n").append(body);
            return new FakeRequest(sb.toString().getBytes(StandardCharsets.ISO_8859_1), tool);
        }

        @SuppressWarnings("unchecked")
        Object dispatch(String name, Object[] a)
        {
            switch (name)
            {
                case "unwrap":
                    return this;
                case "toByteArray":
                    return byteArray(raw);
                case "bodyOffset":
                    return bodyOffset();
                case "httpVersion":
                    return httpVersion();
                case "httpService":
                    return SERVICE;
                case "toolSource":
                    return proxy(ToolSource.class, (n, x) -> n.equals("toolType") ? tool
                            : n.equals("isFromTool") ? java.util.Arrays.asList((Object[]) x[0]).contains(tool) : null);
                case "annotations":
                    return ANNOTATIONS;
                case "url":
                    return "https://target.local" + path();
                case "method":
                    return requestLine().split(" ")[0];
                case "path":
                    return path();
                case "headers":
                {
                    List<HttpHeader> hs = new ArrayList<>();
                    for (String[] h : headerPairs())
                    {
                        hs.add(header(h[0], h[1]));
                    }
                    return hs;
                }
                case "body":
                    return byteArray(body().getBytes(StandardCharsets.ISO_8859_1));
                case "withPath":
                    return rebuild((String) a[0], headerPairs(), body(), false).self;
                case "withUpdatedHeader":
                {
                    List<String[]> hs = headerPairs();
                    for (String[] h : hs)
                    {
                        if (h[0].equalsIgnoreCase((String) a[0]))
                        {
                            h[1] = (String) a[1];
                            break;
                        }
                    }
                    return rebuild(path(), hs, body(), false).self;
                }
                case "withRemovedHeaders":
                {
                    List<String[]> hs = headerPairs();
                    for (HttpHeader rm : (List<HttpHeader>) a[0])
                    {
                        for (int i = 0; i < hs.size(); i++)
                        {
                            if (hs.get(i)[0].equalsIgnoreCase(rm.name()) && hs.get(i)[1].equals(rm.value()))
                            {
                                hs.remove(i);
                                break;
                            }
                        }
                    }
                    return rebuild(path(), hs, body(), false).self;
                }
                case "withAddedHeaders":
                {
                    List<String[]> hs = headerPairs();
                    for (HttpHeader h : (List<HttpHeader>) a[0])
                    {
                        hs.add(new String[]{h.name(), h.value()});
                    }
                    return rebuild(path(), hs, body(), false).self;
                }
                case "withBody":
                    return rebuild(path(), headerPairs(),
                            new String(((ByteArray) a[0]).getBytes(), StandardCharsets.ISO_8859_1), true).self;
                case "hashCode":
                    return System.identityHashCode(this);
                case "equals":
                    return a[0] == self;
                case "toString":
                    return str();
                default:
                    throw new UnsupportedOperationException("FakeRequest." + name);
            }
        }
    }

    /** Permite recuperar el FakeRequest desde el proxy. */
    interface Unwrap
    {
        FakeRequest unwrap();
    }

    private static FakeRequest unwrap(Object o)
    {
        return ((Unwrap) o).unwrap();
    }

    private static void installFactory()
    {
        ObjectFactoryLocator.FACTORY = proxy(MontoyaObjectFactory.class, (name, a) -> switch (name)
        {
            case "byteArray" -> byteArray((byte[]) a[0]);
            case "httpHeader" -> header((String) a[0], (String) a[1]);
            case "httpRequest" -> new FakeRequest(((ByteArray) a[1]).getBytes(), ToolType.REPEATER).self;
            case "requestResult" -> action((HttpRequest) a[0]);
            default -> throw new UnsupportedOperationException("factory." + name);
        });
    }

    private static RequestToBeSentAction action(HttpRequest request)
    {
        FakeRequest fr = unwrap(request);
        return proxy(RequestToBeSentAction.class, (n, a) -> switch (n)
        {
            case "request" -> fr;
            case "annotations" -> ANNOTATIONS;
            default -> null;
        });
    }

    private static ByteArray byteArray(byte[] data)
    {
        byte[] copy = data.clone();
        return proxy(ByteArray.class, (n, a) -> switch (n)
        {
            case "getBytes" -> copy.clone();
            case "length" -> copy.length;
            case "toString" -> new String(copy, StandardCharsets.ISO_8859_1);
            default -> throw new UnsupportedOperationException("ByteArray." + n);
        });
    }

    private static HttpHeader header(String name, String value)
    {
        return proxy(HttpHeader.class, (n, a) -> switch (n)
        {
            case "name" -> name;
            case "value" -> value;
            case "toString" -> name + ": " + value;
            default -> throw new UnsupportedOperationException("HttpHeader." + n);
        });
    }

    private static MontoyaApi api()
    {
        Logging logging = proxy(Logging.class, (n, a) -> {
            if (n.startsWith("log"))
            {
                logs.add(String.valueOf(a[0]));
                if (a.length > 1 && a[1] instanceof Throwable t)
                {
                    t.printStackTrace();
                }
            }
            return null;
        });
        return proxy(MontoyaApi.class, (n, a) -> n.equals("logging") ? logging : null);
    }

    private static Preferences preferences(Map<String, Object> data)
    {
        return proxy(Preferences.class, (n, a) -> {
            if (n.startsWith("get"))
            {
                return data.get((String) a[0]);
            }
            if (n.startsWith("set"))
            {
                data.put((String) a[0], a[1]);
            }
            return null;
        });
    }

    interface Handler
    {
        Object handle(String method, Object[] args);
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, Handler h)
    {
        return (T) Proxy.newProxyInstance(HandlerSimulation.class.getClassLoader(), new Class<?>[]{type},
                (p, m, args) -> {
                    Object r = h.handle(m.getName(), args == null ? new Object[0] : args);
                    if (r instanceof FakeRequest fr)
                    {
                        return fr.self;
                    }
                    return r;
                });
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
}
