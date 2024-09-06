package angrintegration.entrypoint;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;

import javax.swing.JComponent;
import javax.swing.JPanel;

import angrintegration.entrypoint.EntryPoint.BlankState;
import docking.widgets.button.GButton;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import generic.theme.GIcon;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.layout.PairLayout;

/**
 * EntryPointView handling a BlankState.
 * 
 * Provides a component to set the entry point address, which will be constrained to the address space
 * of the currently running program.
 */
public class BlankStateView extends EntryPointView {
	
	private JPanel panel;
	private IntegerTextField addressField;
	private CodeViewerService codeViewerService;
	
	public BlankStateView() {
		panel = new JPanel(new PairLayout(5,5));
		
		panel.add(new GLabel("Address:"));
		addressField = new IntegerTextField();
		addressField.getComponent().setToolTipText("The address of the program to load");
		
		var addressPanel = new JPanel(new BorderLayout());
		
		var syncAddressButton = new GButton(new GIcon("icon.navigate.in"));
		syncAddressButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				addressField.setText("0x" + codeViewerService
									.getCurrentLocation()
									.getAddress()
									.getOffsetAsBigInteger()
									.toString(16));
				codeViewerService.getListingPanel().updateDisplay(false);
			}
		});
		syncAddressButton.setToolTipText("Synchronize with Ghidra");
		
		addressPanel.add(addressField.getComponent(), BorderLayout.CENTER);
		addressPanel.add(syncAddressButton, BorderLayout.LINE_END);
		
		panel.add(addressPanel);
	}
	
	@Override
	public JComponent getComponent() {
		return panel;
	}
	
	public void setAddress(Address newAddr) {
		this.addressField.setText("0x" + newAddr.getOffsetAsBigInteger().toString(16));
		codeViewerService.getListingPanel().updateDisplay(false);
	}

	@Override
	public EntryPoint getConfig(Program p) {
		BigInteger addr_int = addressField.getValue();
		var factory = p.getAddressFactory();
		if (addr_int != null) {
			var addr = factory.getAddress(addr_int.toString(16));
			return new EntryPoint.BlankState(addr);
		}
		return new EntryPoint.BlankState(null);
	}
	
	@Override
	public void reset() {
		addressField.setText("");
	}

	@Override
	public void updatePanel(EntryPoint e) {
		if (!(e instanceof EntryPoint.BlankState)) {
			throw new IllegalArgumentException();
		}
		var entryPoint = (EntryPoint.BlankState) e;
		addressField.setText("0x" + entryPoint.addr.getOffsetAsBigInteger().toString(16));
		codeViewerService.getListingPanel().updateDisplay(false);
	}
	
	@Override
	public String getDisplayName() {
		return "Blank State";
	}
	
	@Override
	public void onProgramActivate(Program newProgram) {
		addressField.setMaxValue(newProgram.getAddressFactory().getDefaultAddressSpace().getMaxAddress().getOffsetAsBigInteger()); 
	}
	
	@Override
	public void onReady(PluginTool tool) {
		this.codeViewerService = tool.getService(CodeViewerService.class);
	}
	
	@Override
	public Class<?> getSupportedClass() {
		return BlankState.class;
	}

	@Override
	public String getToolTipText() {
		return "Start at a blank state, with no registers or memory set";
	}

}
