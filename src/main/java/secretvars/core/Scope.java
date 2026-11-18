package secretvars.core;

/**
 * Dónde se guarda un secreto.
 * PROJECT: dentro del fichero de proyecto de Burp (específico de la auditoría).
 * GLOBAL:  en las preferencias de usuario de Burp (disponible en todos los proyectos).
 * Si existe el mismo nombre en ambos ámbitos, prevalece el de proyecto.
 */
public enum Scope
{
    PROJECT("Proyecto"),
    GLOBAL("Global");

    private final String label;

    Scope(String label)
    {
        this.label = label;
    }

    public String label()
    {
        return label;
    }

    @Override
    public String toString()
    {
        return label;
    }
}
