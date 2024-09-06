package angrintegration.exploregoal;

import angrintegration.exploregoal.ExploreGoal.TerminationGoal;
import ghidra.program.model.listing.Program;

public class TerminationGoalView extends ExploreGoalView {

	// TerminationCondition has no config options; not much to do here
	
	@Override
	public ExploreGoal getConfig(Program p) {
		return new TerminationGoal();
	}
	
	@Override
	public void reset() {
		// nothing to do	
	}

	@Override
	public void updatePanel(ExploreGoal e) {
		// nothing to do
	}

	@Override
	public String getDisplayName() {
		return "Termination";
	}

	@Override
	public Class<?> getSupportedClass() {
		return TerminationGoal.class;
	}
	
	@Override
	public String getToolTipText() {
		return "Stop when all states have no further execution to do";
	}
}
