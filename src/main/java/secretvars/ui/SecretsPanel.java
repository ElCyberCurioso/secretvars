package secretvars.ui;

import burp.api.montoya.core.ToolType;
import secretvars.burp.Settings;
import secretvars.core.PlaceholderEngine;
import secretvars.core.Secret;
import secretvars.core.SecretStore;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

/** Pestaña principal: gestión de secretos y ajustes. */
public final class SecretsPanel extends JPanel
{
    private static final EnumSet<ToolType> HIDDEN_TOOLS = EnumSet.of(ToolType.DECODER, ToolType.COMPARER);

    private final SecretStore store;
    private final Consumer<Component> theme;
    private final SecretsTableModel model = new SecretsTableModel();
    private final JTable table = new JTable(model);
    private final JCheckBox showValues = new JCheckBox("Mostrar valores");
    private final Runnable storeListener = () -> SwingUtilities.invokeLater(this::reload);
    private final Timer usageTimer;

    public SecretsPanel(SecretStore store, Settings settings, Consumer<Component> theme)
    {
        super(new BorderLayout(0, 8));
        this.store = store;
        this.theme = theme;
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // --- cabecera
        JLabel help = new JLabel("<html><b>SecretVars</b> &mdash; escribe <code>{{secret:NOMBRE}}</code> en cualquier parte "
                + "de una petición (línea de petición, cabeceras o cuerpo).<br>"
                + "El valor real se inserta al enviar; el editor (Repeater, Intruder...) conserva el marcador, así que "
                + "cambiar un valor aquí afecta a todos los envíos posteriores sin tocar las pestañas guardadas.<br>"
                + "Modificadores encadenables: <code>|url</code> <code>|b64</code> <code>|b64url</code> "
                + "<code>|hex</code> <code>|json</code> &mdash; p. ej. <code>Authorization: Basic {{secret:creds|b64}}</code>"
                + "</html>");
        add(help, BorderLayout.NORTH);

        // --- tabla
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setAutoCreateRowSorter(false);
        table.setRowSorter(new TableRowSorter<>(model));
        table.setFillsViewportHeight(true);
        int[] widths = {170, 130, 300, 300, 60, 80};
        for (int i = 0; i < widths.length; i++)
        {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        table.addMouseListener(new MouseAdapter()
        {
            @Override
            public void mouseClicked(MouseEvent e)
            {
                if (e.getClickCount() == 2 && table.rowAtPoint(e.getPoint()) >= 0)
                {
                    editSelected();
                }
            }
        });

        JButton add = new JButton("Añadir");
        JButton edit = new JButton("Editar");
        JButton remove = new JButton("Eliminar");
        JButton copy = new JButton("Copiar marcador");
        add.addActionListener(e -> SecretDialog.show(this, store, null, null, theme));
        edit.addActionListener(e -> editSelected());
        remove.addActionListener(e -> removeSelected());
        copy.addActionListener(e -> copySelectedPlaceholders());
        showValues.addActionListener(e -> model.fireTableDataChanged());

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        toolbar.add(add);
        toolbar.add(edit);
        toolbar.add(remove);
        toolbar.add(copy);
        toolbar.add(Box.createHorizontalStrut(16));
        toolbar.add(showValues);

        JPanel center = new JPanel(new BorderLayout(0, 6));
        center.add(toolbar, BorderLayout.NORTH);
        center.add(new JScrollPane(table), BorderLayout.CENTER);
        add(center, BorderLayout.CENTER);

        // --- ajustes
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsPanel.setBorder(BorderFactory.createTitledBorder("Ajustes"));

        JCheckBox enabled = new JCheckBox("Sustitución activada", settings.enabled());
        enabled.addActionListener(e -> settings.setEnabled(enabled.isSelected()));
        JPanel row1 = flow();
        row1.add(enabled);
        settingsPanel.add(row1);

        JPanel row2 = new JPanel(new BorderLayout(8, 0));
        row2.setAlignmentX(LEFT_ALIGNMENT);
        row2.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        JLabel applyLabel = new JLabel("Aplicar en:");
        applyLabel.setVerticalAlignment(JLabel.TOP);
        applyLabel.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
        row2.add(applyLabel, BorderLayout.WEST);
        JPanel toolsGrid = new JPanel(new GridLayout(0, 6, 6, 0));
        for (ToolType t : ToolType.values()) // en tiempo de ejecución: compatible con herramientas nuevas/antiguas
        {
            if (HIDDEN_TOOLS.contains(t))
            {
                continue;
            }
            JCheckBox cb = new JCheckBox(t.toolName(), settings.isToolEnabled(t));
            cb.setToolTipText(t.toolName());
            cb.addActionListener(e -> settings.setToolEnabled(t, cb.isSelected()));
            toolsGrid.add(cb);
        }
        row2.add(toolsGrid, BorderLayout.CENTER);
        settingsPanel.add(row2);

        JCheckBox log = new JCheckBox("Registrar cada sustitución en la pestaña Output de la extensión (solo nombres, nunca valores)",
                settings.logSubstitutions());
        log.addActionListener(e -> settings.setLogSubstitutions(log.isSelected()));
        JPanel row3 = flow();
        row3.add(log);
        settingsPanel.add(row3);

        JLabel note = new JLabel("<html><small>Los valores se guardan sin cifrar: ámbito Proyecto en el fichero .burp; "
                + "ámbito Global en las preferencias de usuario de Burp. Las peticiones realmente enviadas (Logger, "
                + "historial) sí contienen el valor.</small></html>");
        JPanel row4 = flow();
        row4.add(note);
        settingsPanel.add(row4);

        add(settingsPanel, BorderLayout.SOUTH);

        store.addListener(storeListener);
        usageTimer = new Timer(1000, e -> {
            if (store.consumeUsageDirty())
            {
                model.fireTableRowsUpdated(0, Math.max(0, model.getRowCount() - 1));
            }
        });
        usageTimer.start();
        reload();
    }

    private static JPanel flow()
    {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        p.setAlignmentX(LEFT_ALIGNMENT);
        return p;
    }

    public void dispose()
    {
        usageTimer.stop();
        store.removeListener(storeListener);
    }

    // ------------------------------------------------------------------ acciones

    private void reload()
    {
        List<Secret> selected = selectedSecrets();
        model.setRows(store.all());
        for (int i = 0; i < model.getRowCount(); i++)
        {
            Secret s = model.rows.get(i);
            if (selected.stream().anyMatch(s::sameIdentity))
            {
                int v = table.convertRowIndexToView(i);
                table.addRowSelectionInterval(v, v);
            }
        }
    }

    private List<Secret> selectedSecrets()
    {
        List<Secret> out = new ArrayList<>();
        for (int v : table.getSelectedRows())
        {
            int m = table.convertRowIndexToModel(v);
            if (m >= 0 && m < model.rows.size())
            {
                out.add(model.rows.get(m));
            }
        }
        return out;
    }

    private void editSelected()
    {
        List<Secret> sel = selectedSecrets();
        if (sel.size() != 1)
        {
            JOptionPane.showMessageDialog(this, "Selecciona un único secreto.", "SecretVars", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        SecretDialog.show(this, store, sel.get(0), null, theme);
    }

    private void removeSelected()
    {
        List<Secret> sel = selectedSecrets();
        if (sel.isEmpty())
        {
            return;
        }
        String names = sel.stream().map(s -> s.name() + " [" + s.scope() + "]").reduce((a, b) -> a + "\n" + b).orElse("");
        if (JOptionPane.showConfirmDialog(this, "¿Eliminar estos secretos?\n\n" + names
                        + "\n\nLas peticiones que los usen enviarán el marcador literal.",
                "SecretVars", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.OK_OPTION)
        {
            sel.forEach(store::remove);
        }
    }

    private void copySelectedPlaceholders()
    {
        List<Secret> sel = selectedSecrets();
        if (sel.isEmpty())
        {
            return;
        }
        String text = sel.stream().map(s -> PlaceholderEngine.placeholder(s.name())).distinct()
                .reduce((a, b) -> a + "\n" + b).orElse("");
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }

    public Optional<Secret> openCreateDialog(Component parent, String presetValue)
    {
        return SecretDialog.show(parent, store, null, presetValue, theme);
    }

    // ------------------------------------------------------------------ modelo

    private final class SecretsTableModel extends AbstractTableModel
    {
        private final String[] columns = {"Nombre", "Ámbito", "Valor", "Descripción", "Usos", "Último uso"};
        private List<Secret> rows = new ArrayList<>();
        private final SimpleDateFormat time = new SimpleDateFormat("HH:mm:ss");

        void setRows(List<Secret> newRows)
        {
            rows = newRows;
            fireTableDataChanged();
        }

        @Override
        public int getRowCount()
        {
            return rows.size();
        }

        @Override
        public int getColumnCount()
        {
            return columns.length;
        }

        @Override
        public String getColumnName(int column)
        {
            return columns[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex)
        {
            return columnIndex == 4 ? Long.class : String.class;
        }

        @Override
        public Object getValueAt(int row, int col)
        {
            Secret s = rows.get(row);
            boolean shadowed = store.isShadowed(s);
            SecretStore.Usage u = shadowed ? null : store.usage(s.name());
            return switch (col)
            {
                case 0 -> s.name();
                case 1 -> shadowed ? s.scope() + " (anulado)" : s.scope().toString();
                case 2 -> showValues.isSelected()
                        ? s.value().replace("\r", "␍").replace("\n", "␊")
                        : (s.value().isEmpty() ? "(vacío)" : "••••••••  (" + s.value().length() + " car.)");
                case 3 -> s.description();
                case 4 -> u == null ? 0L : u.count();
                case 5 -> u == null || u.lastUsedMillis() == 0 ? "" : time.format(new Date(u.lastUsedMillis()));
                default -> "";
            };
        }
    }
}
