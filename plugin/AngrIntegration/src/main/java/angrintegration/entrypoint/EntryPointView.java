package angrintegration.entrypoint;

import angrintegration.OptionalComponent;
import ghidra.program.model.listing.Program;

/**
 * Abstract base class representing a EntryPoint's configuration options.
 */
public abstract class EntryPointView extends OptionalComponent {
	/**
	 * Uses the internal component state to generate an EntryPoint object corresponding to the values of the component's fields
	 */
	public abstract EntryPoint getConfig(Program p);
	
	/**
	 * Reads the state of an entry point and populates its fields with the encapsulated values.
	 * @param e the entry point to read from
	 */
	public abstract void updatePanel(EntryPoint e);	
	

	
}
