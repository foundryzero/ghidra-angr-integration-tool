package angrintegration.entrypoint;

import angrintegration.entrypoint.EntryPoint.EntryState;
import ghidra.program.model.listing.Program;

/**
 * An EntryPointView corresponding to an Entry State i.e. starting at the program's main entry point.
 */
public class EntryStateView extends EntryPointView {

	// Entry state has no configuration options, so there's very little to do here
	
	@Override
	public EntryPoint getConfig(Program p) {
		return new EntryPoint.EntryState();
	}
	
	@Override
	public void reset() {
		// nothing to do
	}
 
	@Override
	public void updatePanel(EntryPoint e) {
		// nothing to do
	}
	
	@Override
	public String getDisplayName() {
		return "Entry State";
	}
	
	@Override
	public Class<?> getSupportedClass() {
		return EntryState.class;
	}
	
	@Override
	public String getToolTipText() {
		return "Start at the entry point of the program";
	}
	
}
