package angrintegration.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.math.BigInteger;
import java.util.ArrayList;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;

import angrintegration.symbolic.ConstraintEntry;
import angrintegration.symbolic.Hook;
import angrintegration.symbolic.Hook.InlineHook;
import angrintegration.symbolic.Hook.SimProcedureHook;
import angrintegration.symbolic.VariableEntry;
import docking.widgets.button.GButton;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import generic.theme.GIcon;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.util.layout.VariableHeightPairLayout;

/**
 * Handles the display of a hook's details.
 * 
 * Unlike the rest of AngrIntegration's UI, this class live-updates it's underlying data rather than generating it on demand.
 * This is because a single HookView needs to handle all the Hooks used in a project, so the data must be stored somewhere other 
 * than the UI text fields.
 */
public class HookView extends JPanel {
	
	/**
	 * The underlying hook being dispalyed
	 */
	Hook hook;
	
	/**
	 * A reference to the currently active program, used to create Addresses and restrict the address input box.
	 */
	private Program program;
	
	private JPanel upper;
	private JPanel lower;
	
	private JCheckBox enabled;
	
	private JTextField nameField;
	
	private IntegerTextField addressField;
	
	private GLabel signatureLabel;
	private JTextField signatureField;  	// used only in SimProcedureHooks
	
	private GLabel lengthLabel;
	private IntegerTextField lengthField;	// used only in InlineHooks
	
	private VariablesTableModel variablesModel;
	private VariablesTable variablesTable;
	
	private ConstraintTableModel constraintsModel;
	private EditableTable constraintsTable;
	
	private JPanel codePanel;
	private JTextArea codeArea;
	
	private static final int COMPONENTS_BEFORE_SIGNATURE_FIELD = 4;
	
	/**
	 * Construct a new HookView.
	 * @param tool the PluginTool, used to aquire services
	 * @param refreshList a lambda that will be run when any of the hook fields are updated, to allow external UI state to know when to refresh.
	 */
	public HookView(PluginTool tool, Runnable dataChanged) {
		super();
		
		this.setLayout(new BorderLayout(5, 5));
		
		upper = new JPanel();
		upper.setLayout(new VariableHeightPairLayout(5, 5));
		
		lower = new JPanel();
		lower.setLayout(new GridLayout(3, 1, 5, 5));
		
		
		upper.add(new JLabel("Name:"));
		
		var nameInner = new JPanel(new BorderLayout(10, 10));
		
		nameField = new JTextField("");
		enabled = new JCheckBox("Enabled");

		nameInner.add(nameField, BorderLayout.CENTER);
		nameInner.add(enabled, BorderLayout.LINE_END);
		upper.add(nameInner);
		
		nameField.getDocument().addDocumentListener(new DocumentListener() {
			
			@Override
			public void insertUpdate(DocumentEvent e) {
				hook.setName(nameField.getText());
				dataChanged.run();
			}
			
			@Override
			public void removeUpdate(DocumentEvent e) {
				insertUpdate(e);
			}
			@Override
			public void changedUpdate(DocumentEvent e) {
				insertUpdate(e);
			}
		});
		
		enabled.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				hook.enabled = enabled.isSelected();
				dataChanged.run();
			}
		});
		
		upper.add(new GLabel("Address: "));
		
		var addressPanel = new JPanel(new BorderLayout());
		addressField = new IntegerTextField();
		addressPanel.add(addressField.getComponent(), BorderLayout.CENTER);
		
		var syncAddressButton = new GButton(new GIcon("icon.navigate.in"));
		syncAddressButton.setToolTipText("Synchronize with listing window");
		syncAddressButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				addressField.setText("0x" + tool.getService(CodeViewerService.class)
									.getCurrentLocation()
									.getAddress()
									.getOffsetAsBigInteger()
									.toString(16));
			}
		});
		
		addressPanel.add(syncAddressButton, BorderLayout.LINE_END);
		
		addressField.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				// Construct an Address of the currently entered value, and write it to the Hook
				var addrInt = addressField.getValue();
				if (addrInt != null) {  // if the field is currently filled with a valid integer
					AddressFactory factory = program.getAddressFactory();
					var addr = factory.getAddress(addrInt.toString(16));
					hook.target = addr;
					
					// Update the signature field with the function pointed to by the address, if present
					var maybeFunc = program.getFunctionManager().getFunctionAt(addr);
					if (maybeFunc != null) {
						signatureField.setText(maybeFunc.getPrototypeString(true, false));
					}
				}
				dataChanged.run();
			}
		});
		
		upper.add(addressPanel);

		
		signatureLabel = new GLabel("Signature: ");
		signatureField = new JTextField();
		upper.add(signatureLabel);
		upper.add(signatureField);
		
		signatureField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				if (hook instanceof SimProcedureHook) {
					var simProcHook = (SimProcedureHook) hook;
					simProcHook.signature = signatureField.getText();
					dataChanged.run();
				}
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				insertUpdate(e);
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				insertUpdate(e);
			}
		});
		
		lengthLabel = new GLabel("Bytes skipped: ");
		lengthField = new IntegerTextField();
		upper.add(lengthLabel);
		upper.add(lengthField.getComponent());
		lengthField.setMaxValue(BigInteger.valueOf(Integer.MAX_VALUE));

		lengthField.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				var inlineHook = (InlineHook) hook; // safe cast: this box can only appear if the current hook is inline
				inlineHook.length = lengthField.getIntValue();
				dataChanged.run();
			}
		});
		
		variablesModel = new VariablesTableModel();
		variablesTable = new VariablesTable("Variables (created/applied when hit)", variablesModel);
		
		variablesModel.addTableModelListener(new TableModelListener() {
			@Override
			public void tableChanged(TableModelEvent e) {
				var entries = new ArrayList<VariableEntry>(variablesModel.getRows()); // force a copy, since the tableModel backer will stay constant
				hook.variables = entries;
				dataChanged.run();
			}
		});

		lower.add(variablesTable.getComponent());
		
		constraintsModel = new ConstraintTableModel(new ConstraintEntry(""), "Constraint");
		constraintsTable = new EditableTable("Constraints", constraintsModel);
		
		constraintsModel.addTableModelListener(new TableModelListener() {
			@Override
			public void tableChanged(TableModelEvent e) {
				var entries = new ArrayList<ConstraintEntry>(constraintsModel.getRows()); // force a copy, since the tableModel backer will stay constant
				hook.constraints = entries;
				dataChanged.run();
			}
		});
		
		lower.add(constraintsTable.getComponent());
		
		codePanel = new JPanel(new BorderLayout());
		codeArea = new JTextArea("# will be executed AFTER the variables and constraints have been applied");
		codePanel.add(new GLabel("Custom handler"), BorderLayout.PAGE_START);
		codePanel.add(new JScrollPane(codeArea), BorderLayout.CENTER);
		
		codeArea.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void removeUpdate(DocumentEvent e) {
				changedUpdate(e);
			}
			@Override
			public void insertUpdate(DocumentEvent e) {
				changedUpdate(e);
			}
			@Override
			public void changedUpdate(DocumentEvent e) {
				hook.customCode = codeArea.getText();
				dataChanged.run();
			}
		});
		
		codeArea.setEditable(true);
		
		
		
		lower.add(codePanel);
		
		this.add(upper, BorderLayout.PAGE_START);
		this.add(lower, BorderLayout.CENTER);
		
		this.setHook(null);
	}
	
	public void setHook(Hook hook) {
		this.hook = hook;
		if (this.hook == null) {
			recursiveSetEnabled(false, this);
		} else {
			recursiveSetEnabled(true, this);
		}
		
		refresh();
	}
	
	/**
	 * Takes the currently selected hook and applies it's data to the components that make up the HookView.
	 */
	public void refresh() {
		if (this.hook == null) {
			return;
		}
		
		nameField.setText(hook.getName());
		enabled.setSelected(hook.enabled);
		
		addressField.setValue(hook.target.getOffsetAsBigInteger());
		addressField.setHexMode();
		
		if (this.hook instanceof InlineHook) {
			upper.remove(signatureField);
			upper.remove(signatureLabel);
			upper.add(lengthLabel, COMPONENTS_BEFORE_SIGNATURE_FIELD);
			upper.add(lengthField.getComponent(), COMPONENTS_BEFORE_SIGNATURE_FIELD+1);
			
			lengthField.setValue(((InlineHook) this.hook).length);
		} else {
			upper.remove(lengthField.getComponent());
			upper.remove(lengthLabel);
			upper.add(signatureLabel, COMPONENTS_BEFORE_SIGNATURE_FIELD);
			upper.add(signatureField, COMPONENTS_BEFORE_SIGNATURE_FIELD+1);		
			
			signatureField.setText(((SimProcedureHook) this.hook).signature);
		}
		
		// Clearing the tableModel will unfortnately fire the tableUpdated event handler, causing the hook.variables field to by synced with 
		// the table, therefore clearing it too, overwriting the iterator!. To avoid this, a shallow copy is made before the clear.
		var variablesCopy = new ArrayList<>(this.hook.variables);
		variablesModel.clear();
		for (var entry : variablesCopy) {
			variablesModel.addRow(new VariableEntry(entry));
		}
		
		var constraintsCopy = new ArrayList<>(this.hook.constraints);
		constraintsModel.clear();
		for (var entry: constraintsCopy) {
			constraintsModel.addRow(new ConstraintEntry(entry));
		}
		
		codeArea.setText(this.hook.customCode);
		
		this.revalidate();
		this.repaint();
	}
	
	/**
	 * Helper method to enable or disable an entire component tree at once.
	 * 
	 * @param enabled the value to set the enabled state to
	 * @param component the root of the tree to enable or disable
	 */
	private void recursiveSetEnabled(@SuppressWarnings("hiding") boolean enabled, Component component) {
		component.setEnabled(enabled);
		if (component instanceof Container) {
			for (var child : ((Container) component).getComponents()) {
				recursiveSetEnabled(enabled, child);
			}
		}
	}
	
	/**
	 * Called when the currently selected program is changed.
	 * @param newProgram the new program currently being activated
	 */
	public void onProgramActivate(Program newProgram) {
		this.program = newProgram;
		this.addressField.setMaxValue(newProgram.getAddressFactory().getDefaultAddressSpace().getMaxAddress().getOffsetAsBigInteger());
		refresh();
	}

}
