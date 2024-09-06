package angrintegration.entrypoint;

import angrintegration.entrypoint.EntryPoint.FullInitState;
import ghidra.program.model.listing.Program;

/**
 * An EntryPointView corresponding to a FullInitState i.e. starting at the very beginning of the program, running initializers, then jumping to the 'real' entry point.
 */
public class FullInitStateView extends EntryPointView {
	
	@Override
	public EntryPoint getConfig(Program p) {
		return new EntryPoint.FullInitState();
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
		return "Full Init State";
	}
	
	@Override
	public Class<?> getSupportedClass() {
		return FullInitState.class;
	}
	
	@Override
	public String getToolTipText() {
		return "Start at the entry point of the program, after running any initializers";
	}
}
