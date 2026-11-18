package secretvars.core;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/** Resultado de sustituir marcadores en un fragmento (o en una petición completa). */
public final class Substitution
{
    private final String output;
    private final int replacements;
    private final Set<String> used;
    private final Set<String> missing;
    private final Set<String> errors;

    Substitution(String output, int replacements, Set<String> used, Set<String> missing, Set<String> errors)
    {
        this.output = output;
        this.replacements = replacements;
        this.used = used;
        this.missing = missing;
        this.errors = errors;
    }

    public static Substitution unchanged(String input)
    {
        return new Substitution(input, 0, new LinkedHashSet<>(), new LinkedHashSet<>(), new LinkedHashSet<>());
    }

    /** Texto resultante (cadena de bytes). */
    public String output()
    {
        return output;
    }

    public boolean changed()
    {
        return replacements > 0;
    }

    public int replacements()
    {
        return replacements;
    }

    /** Nombres de variables sustituidas. */
    public Set<String> used()
    {
        return Collections.unmodifiableSet(used);
    }

    /** Nombres referenciados pero no definidos (el marcador se deja tal cual). */
    public Set<String> missing()
    {
        return Collections.unmodifiableSet(missing);
    }

    /** Errores de sintaxis, p. ej. modificadores desconocidos (el marcador se deja tal cual). */
    public Set<String> errors()
    {
        return Collections.unmodifiableSet(errors);
    }

    /** Combina estadísticas de varios fragmentos; el output del resultado no es significativo. */
    public static Substitution mergeStats(Substitution... parts)
    {
        int count = 0;
        Set<String> u = new LinkedHashSet<>();
        Set<String> m = new LinkedHashSet<>();
        Set<String> e = new LinkedHashSet<>();
        for (Substitution p : parts)
        {
            if (p == null)
            {
                continue;
            }
            count += p.replacements;
            u.addAll(p.used);
            m.addAll(p.missing);
            e.addAll(p.errors);
        }
        return new Substitution("", count, u, m, e);
    }

    public boolean hasProblems()
    {
        return !missing.isEmpty() || !errors.isEmpty();
    }
}
