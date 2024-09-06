package angrintegration.exploregoal;

import java.util.ArrayList;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;

import angrintegration.ui.EditableTable;
import angrintegration.ui.ListTableModel;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.layout.VerticalLayout;

/**
 * An ExploreGoalView wrapping an AddressGoal. 
 * 
 * Provides configuration UI for the list of addresses that should be it's goal.
 */
public class AddressGoalView extends ExploreGoalView {

	private JPanel panel;
	private ListTableModel<String> model;
	private EditableTable table;
	
	private CodeViewerService codeViewerService;
	
	public AddressGoalView() {
		panel = new JPanel(new VerticalLayout(5));
		model = new ListTableModel<String>("0x0", "Target Address");
		table = new EditableTable("Addresses", model);
		
		table.addTableModelListener(new TableModelListener() {
			@Override
			public void tableChanged(TableModelEvent e) {
				if (codeViewerService != null) {
					codeViewerService.getListingPanel().updateDisplay(true);
				}
			}
		});
		
		panel.add(table.getComponent());
	}
	
	@Override
	public JComponent getComponent() {
		return panel;
	}
	
	@Override
	public ExploreGoal getConfig(Program p) {
		var factory = p.getAddressFactory();
		var newAddrs = new ArrayList<Address>();
		
		for (var addrStr : table.getModel().getRows()) {
			newAddrs.add(factory.getAddress((String) addrStr)); // yes, it is a string, java generics are silly
		}
		return new ExploreGoal.AddressGoal(newAddrs);
	}

	@Override
	public void reset() {
		model.clear();
	}
	
	@Override
	public void updatePanel(ExploreGoal e) {
		if (!(e instanceof ExploreGoal.AddressGoal)) {
			throw new IllegalArgumentException();
		}
		
		var goal = (ExploreGoal.AddressGoal) e;
		
		model.clear();
		for (var addr : goal.addresses) {
			addAddress(addr);
		}
	}
	
	/**
	 * Adds a new address to the internal table, if it's not already there.
	 * @param addr the address to add
	 * @return true if the address was actually added to the table, false if it was already there
	 */
	public boolean addAddress(Address addr) {
		String addrString = "0x" + addr.getOffsetAsBigInteger().toString(16);
		
		if (!model.getRows().contains(addrString)) {
			model.addRow(addrString);
			return true;
		}
		
		return false;
	}

	@Override
	public String getDisplayName() {
		return "Target Address";
	}

	@Override
	public Class<?> getSupportedClass() {
		return ExploreGoal.AddressGoal.class;
	}
	
	@Override
	public String getToolTipText() {
		return "Stop when reaching one of a set of addresses";
	}
	
	@Override
	public void onReady(PluginTool tool) {
		this.codeViewerService = tool.getService(CodeViewerService.class);
	}
}
