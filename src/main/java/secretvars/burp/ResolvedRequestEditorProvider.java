package secretvars.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import secretvars.core.Http1Rewriter;
import secretvars.core.PlaceholderEngine;
import secretvars.core.SecretStore;
import secretvars.core.Substitution;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.util.function.Function;

/**
 * Pestaña de solo lectura "SecretVars" dentro de los editores de petición, visible cuando la
 * petición contiene marcadores. Muestra la petición tal y como se enviaría y qué variables se
 * resuelven. Por defecto enmascara los valores.
 */
public final class ResolvedRequestEditorProvider implements HttpRequestEditorProvider
{
    private static final String MASK = "********";

    private final MontoyaApi api;
    private final SecretStore store;

    public ResolvedRequestEditorProvider(MontoyaApi api, SecretStore store)
    {
        this.api = api;
        this.store = store;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext)
    {
        return new ResolvedEditor();
    }

    private final class ResolvedEditor implements ExtensionProvidedHttpRequestEditor
    {
        private final RawEditor raw = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        private final JLabel status = new JLabel(" ");
        private final JCheckBox reveal = new JCheckBox("Mostrar valores reales");
        private final JPanel panel = new JPanel(new BorderLayout());
        private HttpRequestResponse current;

        ResolvedEditor()
        {
            JPanel top = new JPanel(new BorderLayout(10, 0));
            top.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
            top.add(status, BorderLayout.CENTER);
            top.add(reveal, BorderLayout.EAST);
            reveal.addActionListener(e -> render());
            panel.add(top, BorderLayout.NORTH);
            panel.add(raw.uiComponent(), BorderLayout.CENTER);
        }

        @Override
        public HttpRequest getRequest()
        {
            // Solo lectura: se devuelve siempre la petición original con sus marcadores.
            return current == null ? null : current.request();
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse)
        {
            current = requestResponse;
            render();
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse)
        {
            try
            {
                return requestResponse != null && requestResponse.request() != null
                        && PlaceholderEngine.mayContain(requestResponse.request().toByteArray().getBytes());
            }
            catch (Throwable t)
            {
                return false;
            }
        }

        @Override
        public String caption()
        {
            return "SecretVars";
        }

        @Override
        public Component uiComponent()
        {
            return panel;
        }

        @Override
        public Selection selectedData()
        {
            return raw.selection().orElse(null);
        }

        @Override
        public boolean isModified()
        {
            return false;
        }

        private void render()
        {
            if (current == null || current.request() == null)
            {
                raw.setContents(ByteArray.byteArray(new byte[0]));
                status.setText(" ");
                return;
            }
            HttpRequest request = current.request();
            boolean show = reveal.isSelected();
            Function<String, String> lookup = show ? store::lookup : n -> store.lookup(n) == null ? null : MASK;

            Http1Rewriter.Result r = Http1Rewriter.rewrite(request.toByteArray().getBytes(), request.bodyOffset(), lookup, show);
            raw.setContents(ByteArray.byteArray(r.bytes()));
            status.setText(describe(r.stats(), r.warnings()));
        }

        private String describe(Substitution s, java.util.List<String> warnings)
        {
            StringBuilder sb = new StringBuilder("<html>");
            sb.append(s.used().isEmpty() ? "Ninguna variable resuelta"
                    : "Resueltas: <b>" + String.join(", ", s.used()) + "</b>");
            if (!s.missing().isEmpty())
            {
                sb.append(" &nbsp;|&nbsp; <font color='#d9534f'>No definidas: <b>")
                        .append(String.join(", ", s.missing())).append("</b></font>");
            }
            for (String e : s.errors())
            {
                sb.append(" &nbsp;|&nbsp; <font color='#d9534f'>").append(escape(e)).append("</font>");
            }
            for (String w : warnings)
            {
                sb.append(" &nbsp;|&nbsp; <font color='#f0ad4e'>").append(escape(w)).append("</font>");
            }
            if (!reveal.isSelected() && s.changed())
            {
                sb.append(" &nbsp;<small>(valores enmascarados; sin modificadores)</small>");
            }
            return sb.append("</html>").toString();
        }

        private String escape(String t)
        {
            return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        }
    }
}
