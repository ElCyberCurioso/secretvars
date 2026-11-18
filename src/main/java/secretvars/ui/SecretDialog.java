package secretvars.ui;

import secretvars.core.PlaceholderEngine;
import secretvars.core.Scope;
import secretvars.core.Secret;
import secretvars.core.SecretStore;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.awt.event.KeyEvent;
import java.util.Optional;
import java.util.function.Consumer;

/** Diálogo modal para crear o editar un secreto. */
public final class SecretDialog
{
    private SecretDialog()
    {
    }

    /**
     * @param existing     secreto a editar, o null para crear uno nuevo
     * @param presetValue  valor inicial al crear (p. ej. la selección del editor), puede ser null
     * @param theme        aplica el tema de Burp al contenido, puede ser null
     * @return el secreto guardado (ya persistido en el almacén), o vacío si se canceló
     */
    public static Optional<Secret> show(Component parent, SecretStore store, Secret existing,
                                        String presetValue, Consumer<Component> theme)
    {
        Window owner = parent == null ? null
                : (parent instanceof Window w ? w : SwingUtilities.getWindowAncestor(parent));
        JDialog dialog = new JDialog(owner, existing == null ? "Nuevo secreto" : "Editar secreto",
                JDialog.ModalityType.APPLICATION_MODAL);

        JTextField name = new JTextField(existing == null ? "" : existing.name(), 28);
        JComboBox<Scope> scope = new JComboBox<>(Scope.values());
        scope.setSelectedItem(existing == null ? Scope.PROJECT : existing.scope());
        JTextArea value = new JTextArea(existing != null ? existing.value() : (presetValue == null ? "" : presetValue), 6, 50);
        value.setLineWrap(true);
        value.setWrapStyleWord(false);
        value.setFont(new Font(Font.MONOSPACED, Font.PLAIN, value.getFont().getSize()));
        JTextField desc = new JTextField(existing == null ? "" : existing.description(), 28);
        JLabel placeholder = new JLabel();
        Runnable updatePlaceholder = () -> {
            String n = name.getText().trim();
            placeholder.setText(PlaceholderEngine.isValidName(n) ? "Marcador: " + PlaceholderEngine.placeholder(n)
                    : "Nombre: letras, dígitos, '_', '-' y '.'");
        };
        updatePlaceholder.run();
        name.getDocument().addDocumentListener(new SimpleDocumentListener(updatePlaceholder));

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(10, 10, 4, 10));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;

        addRow(form, c, 0, "Nombre:", name, false);
        addRow(form, c, 1, "", placeholder, false);
        addRow(form, c, 2, "Ámbito:", scope, false);
        addRow(form, c, 3, "Valor:", new JScrollPane(value), true);
        addRow(form, c, 4, "Descripción:", desc, false);

        JLabel scopeHelp = new JLabel("<html><small>Proyecto: se guarda en el fichero de proyecto de Burp. "
                + "Global: en las preferencias de usuario, disponible en todos los proyectos. "
                + "Si existe en ambos, prevalece el de proyecto.</small></html>");
        c.gridx = 1;
        c.gridy = 5;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        form.add(scopeHelp, c);

        Secret[] result = new Secret[1];
        JButton ok = new JButton("Guardar");
        JButton cancel = new JButton("Cancelar");
        ok.addActionListener(e -> {
            String n = name.getText().trim();
            String v = value.getText();
            if (!PlaceholderEngine.isValidName(n))
            {
                JOptionPane.showMessageDialog(dialog, "Nombre no válido: use solo letras, dígitos, '_', '-' y '.'",
                        "SecretVars", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if ((v.contains("\n") || v.contains("\r")) && JOptionPane.showConfirmDialog(dialog,
                    "El valor contiene saltos de línea (¿pegado con un salto final?).\n"
                            + "Si se usa en una cabecera, partirá la cabecera en dos. ¿Guardar igualmente?",
                    "SecretVars", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE) != JOptionPane.YES_OPTION)
            {
                return;
            }
            Secret updated = new Secret(n, v, (Scope) scope.getSelectedItem(), desc.getText().trim());
            try
            {
                store.upsert(existing, updated);
                result[0] = updated;
                dialog.dispose();
            }
            catch (IllegalArgumentException ex)
            {
                JOptionPane.showMessageDialog(dialog, ex.getMessage(), "SecretVars", JOptionPane.WARNING_MESSAGE);
            }
        });
        cancel.addActionListener(e -> dialog.dispose());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(cancel);
        buttons.add(ok);

        JPanel content = new JPanel(new BorderLayout());
        content.add(form, BorderLayout.CENTER);
        content.add(buttons, BorderLayout.SOUTH);
        dialog.setContentPane(content);
        dialog.getRootPane().setDefaultButton(ok);
        dialog.getRootPane().registerKeyboardAction(e -> dialog.dispose(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);
        if (theme != null)
        {
            try
            {
                theme.accept(content);
            }
            catch (Throwable ignored)
            {
                // API de temas no disponible en versiones antiguas de Burp
            }
        }
        dialog.pack();
        dialog.setMinimumSize(new Dimension(560, dialog.getHeight()));
        dialog.setLocationRelativeTo(owner);
        if (existing == null && presetValue != null)
        {
            SwingUtilities.invokeLater(name::requestFocusInWindow);
        }
        dialog.setVisible(true);
        return Optional.ofNullable(result[0]);
    }

    private static void addRow(JPanel p, GridBagConstraints c, int row, String label, Component field, boolean grow)
    {
        c.gridx = 0;
        c.gridy = row;
        c.weightx = 0;
        c.weighty = 0;
        c.fill = GridBagConstraints.NONE;
        c.anchor = grow ? GridBagConstraints.NORTHWEST : GridBagConstraints.WEST;
        p.add(new JLabel(label), c);
        c.gridx = 1;
        c.weightx = 1;
        c.weighty = grow ? 1 : 0;
        c.fill = grow ? GridBagConstraints.BOTH : GridBagConstraints.HORIZONTAL;
        p.add(field, c);
    }
}
