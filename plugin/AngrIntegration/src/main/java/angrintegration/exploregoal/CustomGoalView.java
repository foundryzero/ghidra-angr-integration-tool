package angrintegration.exploregoal;

import java.awt.BorderLayout;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JTextArea;

import angrintegration.exploregoal.ExploreGoal.CustomGoal;
import angrintegration.ui.ForceNoHorizontalScrollPanel;
import docking.widgets.label.GLabel;
import generic.theme.GColor;
import ghidra.program.model.listing.Program;

/**
 * An ExploreGoalView wrapping an CustomGoal.
 * 
 * Provides configuration UI allowing for the custom python handler to be edited.
 */
public class CustomGoalView extends ExploreGoalView {

	private static final String DEFAULT_TEXT = "# should return true if this state is good!\ndef filter(st: angr.SimState) -> bool:\n  return False\n";
	
	private ForceNoHorizontalScrollPanel panel;
	private JTextArea codeBox;
	
	public CustomGoalView() {
		panel = new ForceNoHorizontalScrollPanel(new BorderLayout());
		codeBox = new JTextArea(DEFAULT_TEXT);

		codeBox.setLineWrap(true);
		codeBox.setBorder(BorderFactory.createLineBorder(new GColor("system.color.bg.border"), 1));
		
		panel.add(codeBox, BorderLayout.CENTER);
		panel.add(new GLabel("Custom Filter Method"), BorderLayout.PAGE_START);
	}
	
	@Override
	public JComponent getComponent() {
		return panel;
	}
	
	@Override
	public ExploreGoal getConfig(Program p) {
		return new CustomGoal(codeBox.getText());
	}
	
	@Override
	public void reset() {
		codeBox.setText(DEFAULT_TEXT);
	}

	@Override
	public void updatePanel(ExploreGoal e) {
		if (!(e instanceof ExploreGoal.CustomGoal)) {
			throw new IllegalArgumentException();
		}
		
		var goal = (ExploreGoal.CustomGoal) e;
		
		codeBox.setText(goal.code);
	}

	@Override
	public String getDisplayName() {
		return "Custom";
	}
	
	@Override
	public Class<?> getSupportedClass() {
		return CustomGoal.class;
	}

	@Override
	public String getToolTipText() {
		return "Stop whenever the provided python function returns True";
	}
	
}
