package secretvars.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Almacén de secretos, seguro para hilos.
 *
 * Las lecturas desde el HttpHandler (muchos hilos, p. ej. Intruder/Scanner) se hacen sobre
 * un mapa inmutable publicado de forma volátil; las escrituras (UI) están sincronizadas y
 * persisten inmediatamente en el backend del ámbito correspondiente.
 */
public final class SecretStore
{
    /** Abstracción del almacenamiento para poder probar sin Burp. */
    public interface Backend
    {
        String load();

        void save(String data);
    }

    public static final class Usage
    {
        private final AtomicLong count = new AtomicLong();
        private volatile long lastUsedMillis;

        public long count()
        {
            return count.get();
        }

        public long lastUsedMillis()
        {
            return lastUsedMillis;
        }
    }

    private static final String FORMAT_HEADER = "SV1";

    private final Map<Scope, Backend> backends;
    private final List<Secret> secrets = new ArrayList<>();
    private volatile Map<String, Secret> effective = Map.of();
    private final ConcurrentHashMap<String, Usage> usage = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<Runnable> listeners = new CopyOnWriteArrayList<>();
    private volatile boolean usageDirty;

    public SecretStore(Map<Scope, Backend> backends)
    {
        this.backends = new EnumMap<>(backends);
    }

    // ------------------------------------------------------------------ carga / guardado

    public synchronized List<String> load()
    {
        List<String> problems = new ArrayList<>();
        secrets.clear();
        for (Scope scope : Scope.values())
        {
            Backend b = backends.get(scope);
            if (b == null)
            {
                continue;
            }
            try
            {
                secrets.addAll(decode(b.load(), scope));
            }
            catch (RuntimeException e)
            {
                problems.add("No se pudieron cargar los secretos de ámbito " + scope + ": " + e.getMessage());
            }
        }
        rebuild();
        return problems;
    }

    private void persist(Scope scope)
    {
        Backend b = backends.get(scope);
        if (b == null)
        {
            return;
        }
        List<Secret> ofScope = secrets.stream().filter(s -> s.scope() == scope).toList();
        b.save(encode(ofScope));
    }

    // ------------------------------------------------------------------ consultas

    /** Valor efectivo (el de proyecto prevalece sobre el global) o null. Llamado desde muchos hilos. */
    public String lookup(String name)
    {
        Secret s = effective.get(name);
        return s == null ? null : s.value();
    }

    public Secret effective(String name)
    {
        return effective.get(name);
    }

    public TreeSet<String> effectiveNames()
    {
        return new TreeSet<>(effective.keySet());
    }

    /** True si este secreto está anulado por otro del mismo nombre con mayor prioridad. */
    public boolean isShadowed(Secret s)
    {
        Secret e = effective.get(s.name());
        return e != null && !e.sameIdentity(s);
    }

    public synchronized List<Secret> all()
    {
        List<Secret> copy = new ArrayList<>(secrets);
        copy.sort(Comparator.comparing(Secret::name, String.CASE_INSENSITIVE_ORDER)
                .thenComparing(Secret::name)
                .thenComparing(Secret::scope));
        return copy;
    }

    public synchronized Optional<Secret> find(Scope scope, String name)
    {
        return secrets.stream().filter(s -> s.scope() == scope && s.name().equals(name)).findFirst();
    }

    public synchronized boolean isEmpty()
    {
        return secrets.isEmpty();
    }

    // ------------------------------------------------------------------ modificaciones

    /**
     * Añade (previous == null) o reemplaza un secreto.
     *
     * @throws IllegalArgumentException si el nombre no es válido o ya existe en ese ámbito
     */
    public void upsert(Secret previous, Secret updated)
    {
        synchronized (this)
        {
            if (!PlaceholderEngine.isValidName(updated.name()))
            {
                throw new IllegalArgumentException(
                        "Nombre no válido: use solo letras, dígitos, '_', '-' y '.'");
            }
            for (Secret s : secrets)
            {
                if (s.sameIdentity(updated) && !s.sameIdentity(previous))
                {
                    throw new IllegalArgumentException(
                            "Ya existe un secreto '" + updated.name() + "' en el ámbito " + updated.scope());
                }
            }
            if (previous != null)
            {
                secrets.removeIf(s -> s.sameIdentity(previous));
            }
            secrets.add(updated);
            rebuild();
            persist(updated.scope());
            if (previous != null && previous.scope() != updated.scope())
            {
                persist(previous.scope());
            }
        }
        fireChanged();
    }

    public void remove(Secret secret)
    {
        synchronized (this)
        {
            secrets.removeIf(s -> s.sameIdentity(secret));
            rebuild();
            persist(secret.scope());
        }
        fireChanged();
    }

    private void rebuild()
    {
        Map<String, Secret> map = new HashMap<>();
        for (Scope scope : new Scope[]{Scope.GLOBAL, Scope.PROJECT}) // proyecto sobrescribe a global
        {
            for (Secret s : secrets)
            {
                if (s.scope() == scope)
                {
                    map.put(s.name(), s);
                }
            }
        }
        effective = Map.copyOf(map);
    }

    // ------------------------------------------------------------------ uso

    public void recordUse(Iterable<String> names)
    {
        long now = System.currentTimeMillis();
        for (String n : names)
        {
            Usage u = usage.computeIfAbsent(n, k -> new Usage());
            u.count.incrementAndGet();
            u.lastUsedMillis = now;
        }
        usageDirty = true;
    }

    public Usage usage(String name)
    {
        return usage.get(name);
    }

    /** Devuelve true (y limpia el indicador) si ha habido usos desde la última llamada. */
    public boolean consumeUsageDirty()
    {
        boolean d = usageDirty;
        usageDirty = false;
        return d;
    }

    // ------------------------------------------------------------------ eventos

    public void addListener(Runnable r)
    {
        listeners.add(r);
    }

    public void removeListener(Runnable r)
    {
        listeners.remove(r);
    }

    private void fireChanged()
    {
        for (Runnable r : listeners)
        {
            r.run();
        }
    }

    // ------------------------------------------------------------------ serialización

    /** Formato: "SV1" y una línea por secreto con base64(nombre):base64(valor):base64(descripción). */
    static String encode(List<Secret> list)
    {
        Base64.Encoder enc = Base64.getEncoder();
        StringBuilder sb = new StringBuilder(FORMAT_HEADER);
        for (Secret s : list)
        {
            sb.append('\n')
                    .append(enc.encodeToString(s.name().getBytes(StandardCharsets.UTF_8))).append(':')
                    .append(enc.encodeToString(s.value().getBytes(StandardCharsets.UTF_8))).append(':')
                    .append(enc.encodeToString(s.description().getBytes(StandardCharsets.UTF_8)));
        }
        return sb.toString();
    }

    static List<Secret> decode(String data, Scope scope)
    {
        List<Secret> out = new ArrayList<>();
        if (data == null || data.isBlank())
        {
            return out;
        }
        String[] lines = data.split("\n");
        if (!FORMAT_HEADER.equals(lines[0].trim()))
        {
            throw new IllegalArgumentException("formato desconocido");
        }
        Base64.Decoder dec = Base64.getDecoder();
        for (int i = 1; i < lines.length; i++)
        {
            String line = lines[i].trim();
            if (line.isEmpty())
            {
                continue;
            }
            String[] f = line.split(":", -1);
            if (f.length < 2)
            {
                continue;
            }
            String name = new String(dec.decode(f[0]), StandardCharsets.UTF_8);
            String value = new String(dec.decode(f[1]), StandardCharsets.UTF_8);
            String desc = f.length > 2 ? new String(dec.decode(f[2]), StandardCharsets.UTF_8) : "";
            if (PlaceholderEngine.isValidName(name))
            {
                out.add(new Secret(name, value, scope, desc));
            }
        }
        return out;
    }
}
