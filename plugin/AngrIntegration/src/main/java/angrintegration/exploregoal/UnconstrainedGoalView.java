package angrintegration.exploregoal;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;

import javax.swing.JComponent;
import javax.swing.JPanel;

import angrintegration.exploregoal.ExploreGoal.UnconstrainedGoal;
import docking.widgets.button.GButton;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import generic.theme.GIcon;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.layout.PairLayout;

public class UnconstrainedGoalView extends ExploreGoalView {

	private JPanel panel;
	private IntegerTextField targetAddressField;
	private CodeViewerService codeViewerService;
	
	public UnconstrainedGoalView() {
		panel = new JPanel(new PairLayout(5, 5));
		
		panel.add(new GLabel("Target Address:"));
		targetAddressField = new IntegerTextField();
		
		var targetAddressPanel = new JPanel(new BorderLayout());
		
		var syncAddressButton = new GButton(new GIcon("icon.navigate.in"));
		syncAddressButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				targetAddressField.setText("0x" + codeViewerService
									.getCurrentLocation()
									.getAddress()
									.getOffsetAsBigInteger()
									.toString(16));
			}
		});
		
		targetAddressPanel.add(targetAddressField.getComponent(), BorderLayout.CENTER);
		targetAddressPanel.add(syncAddressButton, BorderLayout.LINE_END);
		
		panel.add(targetAddressPanel);
	}
	
	@Override
	public JComponent getComponent() {
		return panel;
	}
	
	@Override
	public ExploreGoal getConfig(Program p) {
		BigInteger addr_int = targetAddressField.getValue();
		var factory = p.getAddressFactory();
		if (addr_int != null) {
			var addr = factory.getAddress(addr_int.toString(16));
			return new UnconstrainedGoal(addr);
		}
		return new UnconstrainedGoal(null);	
	}
	
	@Override
	public void reset() {
		targetAddressField.setText("");
	}

	@Override
	public void updatePanel(ExploreGoal e) {
		if (!(e instanceof UnconstrainedGoal)) {
			throw new IllegalArgumentException();
		}
		var goal = (UnconstrainedGoal) e;
		if (goal.target == null) {
			return;  // target is optional, so might not be present!
		}
		targetAddressField.setText("0x"+ goal.target.getOffsetAsBigInteger().toString(16));
	}

	@Override
	public String getDisplayName() {
		return "Unconstrained IP";
	}
	
	@Override
	public void onProgramActivate(Program newProgram) {
		targetAddressField.setMaxValue(newProgram.getAddressFactory().getDefaultAddressSpace().getMaxAddress().getOffsetAsBigInteger()); 
	}
	
	@Override
	public void onReady(PluginTool tool) {
		this.codeViewerService = tool.getService(CodeViewerService.class);
	}
	
	
	@Override
	public Class<?> getSupportedClass() {
		return UnconstrainedGoal.class;
	}
	
	@Override
	public String getToolTipText() {
		return "Stop whenever a state is reached where the instruction pointer has more than 256 possible symbolic values";
	}

}
