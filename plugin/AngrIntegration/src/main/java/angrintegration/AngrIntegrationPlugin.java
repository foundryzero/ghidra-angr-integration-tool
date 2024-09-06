/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package angrintegration;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.bean.opteditor.OptionsVetoException;

/**
 * Provides angr integration for Ghidra. With support of various architecture files, enables symbolic execution of specific
 * functions or entire programs from within Ghidra.
 * 
 * Requires a virtual environment with a compatible version of angr installed, which should be specified in the plugin settings once installed.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = "angr integration",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Integrates the symbolic execution tool angr",
	description = "Integrates the symbolic execution tool angr",
	servicesRequired = { 
			ProgramManager.class, 
			ConsoleService.class, 
			InterpreterPanelService.class,
			CodeViewerService.class
		}
)
//@formatter:on
public class AngrIntegrationPlugin extends ProgramPlugin implements OptionsChangeListener {

	/**
	 * Provides the main plugin UI.
	 */
	AngrIntegrationProvider provider;
	
	/**
	 * The virtual environment to use.
	 * 
	 * This must contain:<ul>
	 * <li> A compatible version of angr (with the fixes to pcode simulation)
	 * <li> Python 3.12+ (untested on older versions)
	 * </ul>
	 */
	File venvDirectory;
	
	/**
	 * The interface used to start angr and communicate with the angr process.
	 */
	AngrInterface angrIf;
	
	// easy access to the console, for logging
	ConsoleService console;
	
	boolean angrIsRunning = false;
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public AngrIntegrationPlugin(PluginTool tool) {
		super(tool);


		
		String pluginName = getName();
		provider = new AngrIntegrationProvider(this, pluginName);

		// Setup the venv path option
		ToolOptions options = tool.getOptions("angr Integration");
		options.addOptionsChangeListener(this);
		options.registerOption("Virtual environment", OptionType.FILE_TYPE, null, null, "The path to the virtual environment containing angr and dependencies");
		
		// Copy the venv value from ghidra's options to the plugin
		loadOptions(options);
		
		// If there's a valid venv, check if it contains the right version of angr
		if (this.angrIf != null) {
			this.angrIf.checkAngrVersion(false);
		}
	}
	
	
	/**
	 * Event handler for program activation.
	 * 
	 * Activation means a new program opening, or the 'active' program changing (e.g. through the listing menu tabs)
	 */
	@Override
	public void programActivated(Program p) {	
		provider.onProgramActivated(p);
	}

	@Override
	public void init() {
		super.init();

		console = tool.getService(ConsoleService.class);
		if (this.angrIf != null) {
			console.addMessage("angr", "Plugin loaded!");
		} else {
			console.addMessage("angr", "Plugin not loaded! Please specify a path to a angr venv.");
		}
		
		// begin kludge, see comments in AngrInfoFieldFactory
		var codeViewer = tool.getService(CodeViewerService.class);
		AngrInfoFieldFactory.plugins.put(codeViewer.getFormatManager(), this);
		// end kludge
		
		provider.onReady(tool); // allow anything in the provider to aquire services it needs
	}
	
	private Path getPythonPathInVenv(File venvDir) {
		if (!System.getProperty("os.name").toLowerCase().contains("windows")) {
			return Paths.get(venvDir.getAbsolutePath(), "bin", "python");
		}
		
		return Paths.get(venvDir.getAbsolutePath(), "Scripts", "python.exe");
	}

	private Path getPythonPathInVenv() {
	    return getPythonPathInVenv(this.venvDirectory);
	}
	
	/**
	 * Start the main angr process!
	 * @param c the AngrConfiguration to run angr with
	 */
	public void startAngr(AngrConfiguration c) {
		
		// Inject ghidra-specific values to the config
		c.baseAddr = currentProgram.getImageBase();
		c.breakPath = Paths.get(Application.getUserTempDirectory().getAbsolutePath(), "angrBreak" + Long.toString(System.currentTimeMillis())).toString();
		
		angrIsRunning = true;
		angrIf.runAngrMain(c);
	}
	
	/**
	 * Forcibly stop all running angr processes.
	 */
	public void stopAngr() {
		angrIf.stopScripts();
		angrIsRunning = false;
		statusReport(""); // clear the status report field
	}

	/**
	 * Callback when the options are changed in the UI.
	 * Throws an OptionsVetoException to disallow the change if a valid venv isn't provided.
	 */
	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue)
			throws OptionsVetoException {
		if (!this.checkOptions(options)) {
			throw new OptionsVetoException("Invalid venv - does this have the correct version of angr in?");
		}
		this.loadOptions(options);	
	}
	
	/**
	 * Read an options structure and apply it's values to the real plugin.
	 * @param options The structure to read
	 */
	public void loadOptions(Options options) {
		this.venvDirectory = options.getFile("Virtual environment", null);
		if (this.venvDirectory != null) {
			this.angrIf = new AngrInterface(getPythonPathInVenv(), this);
		} else {
			Msg.showWarn(this, null, "Virtual environment not set!", "Please set up a virtual environment containing angr, and provide a path to it in the tool options.");
		}
	}
	
	/**
	 * Check if a given options structure contains a valid version of angr.
	 * 
	 * Performance note: this blocks whilst starting a full python instance, so can be quite slow.
	 * 
	 * @param options the options to check
	 * @return true if the provided options are valid
	 */
	public boolean checkOptions(Options options) {
		var testVenvDirectory = options.getFile("Virtual environment", null);
		if(testVenvDirectory == null) {
		    // Allow an empty path while checking options - this corresponds to nothing
		    // having been set yet, rather than a bad path having been set. A warning will
		    // be shown by loadOptions, but we don't want to prevent this field being empty.
		    return true;
		}
        var testAngrIf = new AngrInterface(getPythonPathInVenv(testVenvDirectory), this);
        return testAngrIf.checkAngrVersion(true);
		
	}
	
	protected void logMessage(String message) {
		this.logMessage("angr", message);
	}
	
	protected void logMessage(String prefix, String message) {
		if (this.console != null) {
			console.addMessage(prefix, message);
		}
	}
	
	protected void logError(String message) {
		this.logMessage("angr", message);
	}
	
	protected void logError(String prefix, String message) {
		if (this.console != null) {
			console.addErrorMessage(prefix, message);
		}
	}
	
	protected void statusReport(String report) {
		provider.onStatusReport(report);
	}
	
	protected void onREPLStart() {
		provider.onREPLStart();
	}
	
	protected void onREPLEnd() {
		provider.onREPLEnd();
	}
	
	protected void refreshListing() {
		var codeViewer = getTool().getService(CodeViewerService.class);
		if (codeViewer != null) {
			codeViewer.getListingPanel().updateDisplay(true);
		}
	}
	
}
