package secretvars.burp;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.persistence.Preferences;

import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Ajustes de la extensión (preferencias de usuario de Burp, comunes a todos los proyectos).
 * Se guardan las herramientas DESACTIVADAS para que cualquier herramienta nueva que añada
 * Burp quede activada por defecto.
 */
public final class Settings
{
    private static final String K_ENABLED = "secretvars.settings.enabled";
    private static final String K_LOG = "secretvars.settings.log";
    private static final String K_DISABLED_TOOLS = "secretvars.settings.disabledTools";

    private final Preferences prefs;
    private volatile boolean enabled;
    private volatile boolean logSubstitutions;
    private final Set<String> disabledTools = ConcurrentHashMap.newKeySet();

    public Settings(Preferences prefs)
    {
        this.prefs = prefs;
        Boolean e = prefs.getBoolean(K_ENABLED);
        enabled = e == null || e;
        Boolean l = prefs.getBoolean(K_LOG);
        logSubstitutions = l != null && l;
        String d = prefs.getString(K_DISABLED_TOOLS);
        if (d != null && !d.isBlank())
        {
            disabledTools.addAll(Arrays.asList(d.split(",")));
        }
    }

    public boolean enabled()
    {
        return enabled;
    }

    public void setEnabled(boolean v)
    {
        enabled = v;
        prefs.setBoolean(K_ENABLED, v);
    }

    public boolean logSubstitutions()
    {
        return logSubstitutions;
    }

    public void setLogSubstitutions(boolean v)
    {
        logSubstitutions = v;
        prefs.setBoolean(K_LOG, v);
    }

    public boolean isToolEnabled(ToolType tool)
    {
        return tool == null || !disabledTools.contains(tool.name());
    }

    public void setToolEnabled(ToolType tool, boolean v)
    {
        if (v)
        {
            disabledTools.remove(tool.name());
        }
        else
        {
            disabledTools.add(tool.name());
        }
        prefs.setString(K_DISABLED_TOOLS, new TreeSet<>(disabledTools).stream().collect(Collectors.joining(",")));
    }
}
