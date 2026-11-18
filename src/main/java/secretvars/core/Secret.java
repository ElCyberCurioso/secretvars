package secretvars.core;

import java.util.Objects;

/** Secreto inmutable identificado por (ámbito, nombre). */
public record Secret(String name, String value, Scope scope, String description)
{
    public Secret
    {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(scope, "scope");
        value = value == null ? "" : value;
        description = description == null ? "" : description;
    }

    public Secret withValue(String newValue)
    {
        return new Secret(name, newValue, scope, description);
    }

    public boolean sameIdentity(Secret other)
    {
        return other != null && scope == other.scope && name.equals(other.name);
    }

    @Override
    public String toString()
    {
        // Nunca exponer el valor en logs ni trazas.
        return "Secret[" + name + ", " + scope + "]";
    }
}
