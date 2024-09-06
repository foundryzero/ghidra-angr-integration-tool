package angrintegration;

import javax.swing.JComponent;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

/**
 * Abstract base class representing a UI component that is only drawn conditionally.
 */
public abstract class OptionalComponent {
	/**
	 * Gets the associated JComponent that should be drawn when the class's option is selected.
	 * Return null to declare that no component is needed (i.e. the component has no options)
	 * @return the component
	 */
	public JComponent getComponent() {
		return null;
	}
	
	/**
	 * Gets the name for the entry point that should be shown in the UI
	 */
	public abstract String getDisplayName();
	
	/**
	 * Gets a medium-length string of text to be shown as the tooltip for the _button to activate this option_ in the UI
	 */
	public abstract String getToolTipText();
	
	/**
	 * Override this to listen to the current program changing.
	 * @param newProgram the program about to be made active
	 */
	public void onProgramActivate(Program newProgram) {
		return;
	}

	/**
	 * Override this to acquire services when the PluginTool is ready for use.
	 * 
	 * This is useful because EntryPointViews are currently constructed statically, before the Plugin object even exists.
	 * @param tool the tool to aquire services from
	 */
	public void onReady(PluginTool tool) {
		return;
	}
	
	/**
	 * Resets the the component back to the state where it was created
	 */
	public abstract void reset();
	
	public abstract Class<?> getSupportedClass();
	
}
