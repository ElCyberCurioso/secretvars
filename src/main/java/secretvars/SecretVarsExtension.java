package secretvars;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Preferences;
import secretvars.burp.ResolvedRequestEditorProvider;
import secretvars.burp.SecretsContextMenu;
import secretvars.burp.SecretsHttpHandler;
import secretvars.burp.Settings;
import secretvars.core.Scope;
import secretvars.core.SecretStore;
import secretvars.ui.SecretsPanel;

import javax.swing.SwingUtilities;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * SecretVars: variables secretas para Burp Suite.
 *
 * Define secretos con nombre y úsalos en cualquier petición como {{secret:NOMBRE}}. El valor se
 * inserta en el momento del envío, de modo que las pestañas de Repeater (y demás editores)
 * conservan el marcador y siempre usan el valor vigente.
 */
public final class SecretVarsExtension implements BurpExtension
{
    public static final String NAME = "SecretVars";
    /** Versión inyectada por Gradle en el manifiesto del JAR (Implementation-Version). */
    public static final String VERSION = resolveVersion();
    private static final String STORAGE_KEY = "secretvars.secrets";

    private static String resolveVersion()
    {
        Package pkg = SecretVarsExtension.class.getPackage();
        String v = pkg == null ? null : pkg.getImplementationVersion();
        return v == null || v.isBlank() ? "dev" : v;
    }

    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName(NAME);

        Preferences prefs = api.persistence().preferences();
        PersistedObject project = api.persistence().extensionData();

        Map<Scope, SecretStore.Backend> backends = new EnumMap<>(Scope.class);
        backends.put(Scope.PROJECT, new SecretStore.Backend()
        {
            @Override
            public String load()
            {
                return project.getString(STORAGE_KEY);
            }

            @Override
            public void save(String data)
            {
                project.setString(STORAGE_KEY, data);
            }
        });
        backends.put(Scope.GLOBAL, new SecretStore.Backend()
        {
            @Override
            public String load()
            {
                return prefs.getString(STORAGE_KEY);
            }

            @Override
            public void save(String data)
            {
                prefs.setString(STORAGE_KEY, data);
            }
        });

        SecretStore store = new SecretStore(backends);
        List<String> problems = store.load();
        problems.forEach(p -> api.logging().logToError("[SecretVars] " + p));

        Settings settings = new Settings(prefs);

        SecretsPanel[] panelRef = new SecretsPanel[1];
        Runnable buildUi = () -> panelRef[0] = new SecretsPanel(store, settings, c -> {
            try
            {
                api.userInterface().applyThemeToComponent(c);
            }
            catch (Throwable ignored)
            {
                // versiones antiguas de Burp
            }
        });
        if (SwingUtilities.isEventDispatchThread())
        {
            buildUi.run();
        }
        else
        {
            try
            {
                SwingUtilities.invokeAndWait(buildUi);
            }
            catch (Exception e)
            {
                throw new IllegalStateException("No se pudo crear la interfaz de SecretVars", e);
            }
        }
        SecretsPanel panel = panelRef[0];

        api.userInterface().registerSuiteTab(NAME, panel);
        api.http().registerHttpHandler(new SecretsHttpHandler(api, store, settings));
        api.userInterface().registerContextMenuItemsProvider(new SecretsContextMenu(api, store, panel));
        api.userInterface().registerHttpRequestEditorProvider(new ResolvedRequestEditorProvider(api, store));
        api.extension().registerUnloadingHandler(panel::dispose);

        int count = store.all().size();
        api.logging().logToOutput(NAME + " " + VERSION + " cargada. Secretos: " + count
                + ". Sintaxis: {{secret:NOMBRE}} o {{secret:NOMBRE|b64|url}}");
    }
}
