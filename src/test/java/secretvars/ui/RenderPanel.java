package secretvars.ui;

import burp.api.montoya.persistence.Preferences;
import secretvars.burp.Settings;
import secretvars.core.Scope;
import secretvars.core.Secret;
import secretvars.core.SecretStore;

import javax.imageio.ImageIO;
import javax.swing.SwingUtilities;
import java.awt.image.BufferedImage;
import java.io.File;
import java.lang.reflect.Proxy;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Renderiza la pestaña a PNG en modo headless para revisar la maquetación. */
public final class RenderPanel
{
    public static void main(String[] args) throws Exception
    {
        Map<String, Object> data = new HashMap<>();
        Preferences prefs = (Preferences) Proxy.newProxyInstance(RenderPanel.class.getClassLoader(),
                new Class<?>[]{Preferences.class}, (p, m, a) -> {
                    if (m.getName().startsWith("get")) return data.get((String) a[0]);
                    if (m.getName().startsWith("set")) data.put((String) a[0], a[1]);
                    return null;
                });
        Map<Scope, SecretStore.Backend> b = new EnumMap<>(Scope.class);
        Map<Scope, String> st = new EnumMap<>(Scope.class);
        for (Scope s : Scope.values())
            b.put(s, new SecretStore.Backend() { public String load() { return st.get(s); } public void save(String d) { st.put(s, d); } });
        SecretStore store = new SecretStore(b);
        store.load();
        store.upsert(null, new Secret("jwt_admin", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig", Scope.PROJECT, "Token de admin (cliente X)"));
        store.upsert(null, new Secret("api_key", "sk_live_123456", Scope.GLOBAL, "Clave API de pruebas"));
        store.upsert(null, new Secret("api_key", "sk_test_999", Scope.PROJECT, "Sobrescribe la global en este proyecto"));
        store.upsert(null, new Secret("creds", "admin:P@ssw0rd", Scope.PROJECT, "Usar con |b64 en Basic"));
        store.recordUse(List.of("jwt_admin", "jwt_admin", "creds"));
        Settings settings = new Settings(prefs);
        BufferedImage[] img = new BufferedImage[1];
        SwingUtilities.invokeAndWait(() -> {
            SecretsPanel panel = new SecretsPanel(store, settings, null);
            panel.setSize(1150, 560);
            panel.doLayout();
            layoutAll(panel);
            img[0] = new BufferedImage(1150, 560, BufferedImage.TYPE_INT_RGB);
            panel.printAll(img[0].getGraphics());
            panel.dispose();
        });
        ImageIO.write(img[0], "png", new File(args[0]));
    }

    private static void layoutAll(java.awt.Container c)
    {
        c.doLayout();
        for (java.awt.Component ch : c.getComponents())
            if (ch instanceof java.awt.Container cc) layoutAll(cc);
    }
}
