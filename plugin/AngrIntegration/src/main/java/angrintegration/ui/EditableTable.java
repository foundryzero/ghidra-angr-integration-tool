package angrintegration.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.event.TableModelListener;
import docking.widgets.button.GButton;
import docking.widgets.label.GLabel;
import docking.widgets.table.GTable;
import ghidra.util.layout.VerticalLayout;
import resources.Icons;

/**
 * An EditableTable wraps a ghidra GTable in some additional components providing an optional title, along with buttons, positioned 
 * to the right of the table, to add and remove rows from the table.
 * 
 * This is <em>not</em> a subclass of GTable, because it only <em>contains</em> a table instance rather than that being the whole thing.
 * For UI display, call getComponent() to get the composite JComponent.
 */
public class EditableTable {
	private GTable table;
	private JPanel buttonPanel;
	private GButton addButton;
	private GButton removeButton;
	
	private JScrollPane scrollPane;
	
	private JPanel component;
	
	/**
	 * Constructs a new EditableTable with no title.
	 * 
	 * Note: The model must be a EditableTableModel since it needs to be able to handle element insertion and deletion. 
	 * @param model the table model to use
	 */
	public EditableTable(EditableTableModel<?> model) {
		this(null, model);
	}
	
	
	/**
	 * Constructs a new EditableTable with provided model, and title.
	 * 
	 * Note: The model must be a EditableTableModel since it needs to be able to handle element insertion and deletion. 
	 * @param title the title of the table (will be made into a label above the table)
	 * @param model the table model to use
	 */
	public EditableTable(String title, EditableTableModel<?> model) {
		this(title, model, new GTable(model));
	}
	
	// this exists so that subclasses can get control over the specific table that gets used, before it's added to the components.
	protected EditableTable(String title, EditableTableModel<?> model, GTable table) {
		component = new JPanel(new BorderLayout(5, 5));
		
		this.table = table;
		table.setFillsViewportHeight(true);
		buttonPanel = new JPanel(new VerticalLayout(5));
		
		addButton = new GButton(Icons.ADD_ICON);
		removeButton = new GButton(Icons.DELETE_ICON);

		addButton.setToolTipText("Add new element");
		removeButton.setToolTipText("Remove currently selected element(s)");
		
		buttonPanel.add(addButton);
		buttonPanel.add(removeButton);
		
		scrollPane = new JScrollPane(table);
		scrollPane.setPreferredSize(new Dimension(0, 150)); // It's important that the width is set to 0 here
		
		addButton.addActionListener(new ActionListener() {		
			@Override
			public void actionPerformed(ActionEvent e) {
				var tableModel = (EditableTableModel<?>) table.getModel(); // safe cast, the table model will always be an
				tableModel.addRow();										  // EditableTableModel
				scrollPane.revalidate();
				scrollPane.repaint();
			}
		});
		
		removeButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				var tableModel = (EditableTableModel<?>) table.getModel();
				tableModel.removeRows(table.getSelectedRows());
				scrollPane.revalidate();
				scrollPane.repaint();
			}
		});
		
		if (title != null) {
			component.add(new GLabel(title), BorderLayout.PAGE_START);
		}
		component.add(scrollPane, BorderLayout.CENTER);
		component.add(buttonPanel, BorderLayout.LINE_END);
	}
	
	
	public GTable getTable() {
		return table;
	}
	
	public JComponent getComponent() {
		return component;
	}
	
	public EditableTableModel<?> getModel() {
		return (EditableTableModel<?>) table.getModel();
	}
	
	// Convenience methods that push through event listeners to the underlying table model
	
	public void addTableModelListener(TableModelListener ac) {
		table.getModel().addTableModelListener(ac);
	}
	
	public void removeTableModelListener(TableModelListener ac) {
		table.getModel().removeTableModelListener(ac);
	}
}
