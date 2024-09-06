package angrintegration.exploregoal;


import angrintegration.OptionalComponent;
import ghidra.program.model.listing.Program;

/**
 * Abstract base class representing an exploration condition's configuration options and UI
 */
public abstract class ExploreGoalView extends OptionalComponent {
	/**
	 * Uses the internal component state to generate an ExploreGoal object corresponding to the values of the component's fields
	 */
	public abstract ExploreGoal getConfig(Program p);
	
	/**
	 * Reads the state of an explore condition and populates its fields with the encapsulated values.
	 * @param e the entry point to read from
	 */
	public abstract void updatePanel(ExploreGoal e);
	
}
