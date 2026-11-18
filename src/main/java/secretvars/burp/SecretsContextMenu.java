package secretvars.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import secretvars.core.Bytes;
import secretvars.core.PlaceholderEngine;
import secretvars.core.Secret;
import secretvars.core.SecretStore;
import secretvars.ui.SecretsPanel;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import java.awt.Component;
import java.awt.Frame;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Menú contextual (Extensions > SecretVars) en los editores de mensajes:
 *  - Insertar variable           (editor de petición editable: Repeater, Intercept...)
 *  - Convertir selección en secreto (crea el secreto y sustituye la selección por el marcador)
 *  - Crear secreto con la selección (en visores de solo lectura y en respuestas)
 *  - Actualizar valor con la selección (p. ej. un token nuevo de la respuesta de login)
 */
public final class SecretsContextMenu implements ContextMenuItemsProvider
{
    private final MontoyaApi api;
    private final SecretStore store;
    private final SecretsPanel panel;

    public SecretsContextMenu(MontoyaApi api, SecretStore store, SecretsPanel panel)
    {
        this.api = api;
        this.store = store;
        this.panel = panel;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        Optional<MessageEditorHttpRequestResponse> maybeEditor = event.messageEditorRequestResponse();
        if (maybeEditor.isEmpty())
        {
            return List.of();
        }
        MessageEditorHttpRequestResponse editor = maybeEditor.get();
        boolean onRequest = editor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST;
        boolean editableRequest = onRequest && event.isFrom(InvocationType.MESSAGE_EDITOR_REQUEST);

        byte[] selection = selectedBytes(editor, onRequest);
        List<Component> items = new ArrayList<>();

        if (editableRequest)
        {
            JMenu insert = new JMenu("Insertar variable");
            Set<String> names = store.effectiveNames();
            if (names.isEmpty())
            {
                JMenuItem none = new JMenuItem("(no hay secretos definidos)");
                none.setEnabled(false);
                insert.add(none);
            }
            for (String n : names)
            {
                JMenuItem item = new JMenuItem(PlaceholderEngine.placeholder(n));
                item.addActionListener(e -> replaceInRequest(editor, PlaceholderEngine.placeholder(n)));
                insert.add(item);
            }
            items.add(insert);
        }

        if (selection != null && selection.length > 0)
        {
            String value = Bytes.decodeSelection(selection);

            if (editableRequest)
            {
                JMenuItem convert = new JMenuItem("Convertir selección en secreto…");
                convert.addActionListener(e -> panel.openCreateDialog(parent(), value)
                        .ifPresent(s -> replaceInRequest(editor, PlaceholderEngine.placeholder(s.name()))));
                items.add(convert);
            }
            else
            {
                JMenuItem create = new JMenuItem("Crear secreto con la selección…");
                create.addActionListener(e -> panel.openCreateDialog(parent(), value));
                items.add(create);
            }

            JMenu update = new JMenu("Actualizar valor con la selección");
            List<Secret> all = store.all();
            if (all.isEmpty())
            {
                JMenuItem none = new JMenuItem("(no hay secretos definidos)");
                none.setEnabled(false);
                update.add(none);
            }
            for (Secret s : all)
            {
                String label = s.name() + "  [" + s.scope() + (store.isShadowed(s) ? ", anulado" : "") + "]";
                JMenuItem item = new JMenuItem(label);
                item.addActionListener(e -> updateValue(s, value));
                update.add(item);
            }
            items.add(update);
        }

        return items;
    }

    private void updateValue(Secret s, String value)
    {
        // Releer por si ha cambiado desde que se abrió el menú.
        Secret current = store.find(s.scope(), s.name()).orElse(null);
        if (current == null)
        {
            return;
        }
        store.upsert(current, current.withValue(value));
        api.logging().logToOutput("[SecretVars] Valor de '" + s.name() + "' [" + s.scope()
                + "] actualizado desde la selección (" + value.length() + " caracteres).");
    }

    /** Sustituye la selección (o inserta en el cursor) por el texto dado en el editor de petición. */
    private void replaceInRequest(MessageEditorHttpRequestResponse editor, String text)
    {
        try
        {
            HttpRequestResponse rr = editor.requestResponse();
            HttpRequest request = rr.request();
            byte[] raw = request.toByteArray().getBytes();
            int start;
            int end;
            Optional<Range> sel = editor.selectionOffsets();
            if (sel.isPresent())
            {
                start = sel.get().startIndexInclusive();
                end = sel.get().endIndexExclusive();
            }
            else
            {
                start = end = editor.caretPosition();
            }
            start = clamp(start, raw.length);
            end = clamp(Math.max(start, end), raw.length);
            byte[] updated = Bytes.splice(raw, start, end, text.getBytes(StandardCharsets.ISO_8859_1));
            editor.setRequest(HttpRequest.httpRequest(request.httpService(), ByteArray.byteArray(updated)));
        }
        catch (Throwable t)
        {
            api.logging().logToError("[SecretVars] No se pudo modificar el editor", t);
            JOptionPane.showMessageDialog(parent(), "No se pudo modificar el editor: " + t.getMessage()
                    + "\nEl marcador es: " + text, "SecretVars", JOptionPane.WARNING_MESSAGE);
        }
    }

    private static byte[] selectedBytes(MessageEditorHttpRequestResponse editor, boolean onRequest)
    {
        Optional<Range> sel = editor.selectionOffsets();
        if (sel.isEmpty())
        {
            return null;
        }
        HttpRequestResponse rr = editor.requestResponse();
        ByteArray source;
        if (onRequest)
        {
            source = rr.request() == null ? null : rr.request().toByteArray();
        }
        else
        {
            source = rr.response() == null ? null : rr.response().toByteArray();
        }
        if (source == null)
        {
            return null;
        }
        byte[] data = source.getBytes();
        int start = clamp(sel.get().startIndexInclusive(), data.length);
        int end = clamp(sel.get().endIndexExclusive(), data.length);
        return end > start ? Arrays.copyOfRange(data, start, end) : null;
    }

    private static int clamp(int v, int max)
    {
        return Math.max(0, Math.min(v, max));
    }

    private Frame parent()
    {
        try
        {
            return api.userInterface().swingUtils().suiteFrame();
        }
        catch (Throwable t)
        {
            return null;
        }
    }
}
