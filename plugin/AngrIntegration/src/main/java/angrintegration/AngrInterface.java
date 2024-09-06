package angrintegration;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import javax.swing.SwingWorker;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * An interface to angr, and more generally python 3, from Ghidra.
 * Each instance represents a full venv, with associated python and angr versions. 
 * For now, requires the specific angr version ANGR_EXPECTED_VERSION.
 */
public class AngrInterface {
	
	private final int[] ANGR_MIN_VERSION = {9, 2, 117};	//9.2.117+
	protected Path pythonPath;
		
	private AngrIntegrationPlugin p;

	private List<AngrSwingWorker<?,?>> runningWorkers;
	
	public AngrInterface(Path pythonPath, AngrIntegrationPlugin p) {
		this.pythonPath = pythonPath;
		this.p = p;
		this.runningWorkers = new ArrayList<AngrSwingWorker<?,?>>();
	}
	
	public AngrInterface(File pythonPath, AngrIntegrationPlugin p) {
		this(pythonPath.toPath(), p);
	}
	
	private abstract class AngrSwingWorker<T, V> extends SwingWorker<T, V> {
		public abstract void brk();
	}
	

	/**
	 * Checks that the angr version is what it should be.
	 * @param block true if the function should block until the script is done executing
	 * @return if block is false, the return value should be ignored. Otherwise, returns true if the angr version is good, and false otherwise.
	 */
	public boolean checkAngrVersion(boolean block) throws AngrException {
		if (block) {
			var scriptResult = this.startScriptBlocking("get_angr_version");
			
			if (scriptResult == null) {
				return false;
			}
			
			return semVerCheck(scriptResult.strip());
		}


		this.startScript("get_angr_version", (version) -> {
			if (version != null) {
				version = version.strip(); // trim trailing newline
			}
						
			if (!semVerCheck(version)) {
				if (version == null) {
					Msg.showError(AngrInterface.class, null, "Angr issue", "Could not detect angr version!");
				} else {
					String minVersion = Arrays.stream(ANGR_MIN_VERSION)
					        .mapToObj(String::valueOf)
					        .collect(Collectors.joining("."));

					Msg.showError(AngrInterface.class, null, "Angr issue", "Warning: found angr version " + version + ", expected minimum " + minVersion);
				}
			}
		});
		
		return true; // return value should be ignored if block is false.
		
	}
	
	/**
	 * Quick and dirty semantic versioning checker
	 * 
	 * @param version the version to be checked
	 * @return true if the verison is greater than or equal to ANGR_MIN_VERSION, false otherwise
	 */
	private boolean semVerCheck(String version) {
		// discard anything after a dash or plus (to just get the core version string)
		version = version.split("\\-")[0];
		version = version.split("\\+")[0];
		
		int i = 0;
		for (var section : version.split("\\.")) {
			if (i >= ANGR_MIN_VERSION.length) {
				return true; // if the MIN_VERSION is a prefix of the real version
			}
			
			if (ANGR_MIN_VERSION[i] < Integer.parseInt(section)) {
				return true;
			} else if (ANGR_MIN_VERSION[i] == Integer.parseInt(section)) {
				// continue to check further parts of the version number
			} else {
				return false;
			}
			i += 1;
		}
		
		return true;
	}	
	
	/**
	 * Sets the current archif module to a sensible one for a given program.
	 * Invokes the `get_best_archif` script to provide a reasonable suggestion.
	 * 
	 * @param program the program to find a sensible archif for
	 */
	public void setSensibleArchitecture(Program program) {
		try {
		String[] args = {Application.getModuleDataSubDirectory("architectures").getAbsolutePath(), program.getLanguageID().toString()};
		this.startScript("get_best_archif", (result) -> {
			// remove prefix from path
			if (result.startsWith("!<* result ")) {
				result = result.substring(11);
			}
			
			p.provider.setArchitecture(result);
		}, args, null);
		} catch (IOException e) {
			Msg.error(this, e);
		}
	}
	
	/**
	 * Starts a python script in a worker thread with the specified name, and default pythonPath, with no additional
	 * arguments.
	 * @param scriptName The name of the script (without a .py extension)
	 * @param onDone A function to be called when the script terminates. It will be passed the full 
	 * 				 (or, in case of very long running scripts, last 10000 characters) of the script's stdout.
	 */
	public void startScript(String scriptName, Consumer<String> onDone) {
		this.startScript(scriptName, onDone, this.pythonPath);
	}
	
	/**
	 * Runs a python script, blocking until completion.
	 * @param scriptName The name of the script to run
	 * @return The stdout of the script
	 */
	public String startScriptBlocking(String scriptName) {
		return this.startScriptBlocking(scriptName, this.pythonPath);
	}
	
	/**
	 * Starts a python script in a worker thread with the specified name and pythonPath, and no arguments.
	 * @param scriptName The name of the script (without a .py extension)
	 * @param onDone A function to be called when the script terminates. It will be passed the full 
	 * 				 (or, in case of very long running scripts, last 10000 characters) of the script's stdout
	 * @param pypath The path to the python executable
	 */
	public void startScript(String scriptName, Consumer<String> onDone, Path pypath) {
		String[] noOptions = {}; // can't use an inline initialiser for strange functional interface reasons
		this.startScript(scriptName, onDone, pypath, noOptions, null);
	}
	
	/**
	 * Starts a python script in a worker thread with the specified name and arguments.
	 * @param scriptName The name of the script (without a .py extension)
	 * @param onDone A function to be called when the script terminates. It will be passed the full 
	 * 				 (or, in case of long running scripts, last 10000 characters) of the script's stdout
	 * @param args An array of arguments to be passed through to the script
	 * @param brkPath The file to create to when brk() is called
	 */
	public void startScript(String scriptName, Consumer<String> onDone, String[] args, Path brkPath) {
		this.startScript(scriptName, onDone, this.pythonPath, args, brkPath);
	}
	
	/**
	 * Starts a python script scriptName in a worker thread with the specified additional arguments, python path, 
	 * and onDone callback.
	 * @param scriptName The name of the script (without a .py extension)
	 * @param onDone A function to be called when the script terminates. It will be passed the full 
	 * 				 (or, in case of long running scripts, last 10000 characters) of the script's stdout
	 * @param pypath The path to the python executable
	 * @param args An array of arguments to be passed through to the script
	 */
	public void startScript(String scriptName, Consumer<String> onDone, Path pypath, String[] args, Path brkPath) {
		var scriptWorker = new AngrSwingWorker<String, Object> () {
			private Process scriptProcess = null;
			private boolean brk = false;
			
			@Override
			public void brk() {
				brk = true;
			}
			
			// the main worker task, executed in it's own thread
			@Override
			protected String doInBackground() {
				try {
					return runScript();
				} catch (Exception e) {  // Catch-all because otherwise the worker will eat the exception and die with no other notification, which isn't great.
					e.printStackTrace();
					Msg.showError(this, null, "Exception in worker!", e);
					return null;
				}
			}

			private String runScript() {
				
				this.scriptProcess = AngrInterface.getScriptProcess(scriptName, pypath, args); // Actually invoke the script
				if (this.scriptProcess == null) {
					return null;
				}
				
				AngrREPL replProvider = null; // used to provide the REPL if the 'drop into REPL' configuration option is selected

				try {
					// initially, output is sent to the ghidra Console. If the REPL starts, output should be redirected there.
					var sendToREPL = false; 

					// Create streams to send and recieve std{in, out, err} from the python process.
					// NOTE: The methods on scriptProcess are somewhat confusingly named -
					// getInputStream represents stdout, because it's <em>input</em> to this thread, and vice versa for stdout.
					
					var stdoutStream = new BufferedReader(new InputStreamReader(this.scriptProcess.getInputStream()));
					var stdinStream = new OutputStreamWriter(this.scriptProcess.getOutputStream());
					stdoutStream.mark(10000); // Allocate a 10000 character buffer for storing past output.
					var stderrStream = new BufferedReader(new InputStreamReader(this.scriptProcess.getErrorStream()));
					
					while (this.scriptProcess.isAlive()) {
						
						this.scriptProcess.waitFor(20, TimeUnit.MILLISECONDS); // check for output every 20ms
						
						if (replProvider != null) {
							replProvider.checkSendInput(); // check if there's any input waiting to come from the REPL, and if so, send it down the process's stdin
						}
						
						// forward a break message down to angr, by way of writing a file to the appropriate location
						if (brk == true) {
							brk = false;
							if (brkPath != null) {
								brkPath.toFile().createNewFile();
							}
						}
						
						while (stderrStream.ready()) {
							if (!sendToREPL) {
								p.logError("angr [" + scriptName + "]", stderrStream.readLine());
							} else {
								char[] buf = new char[2000];
								stderrStream.read(buf);
								replProvider.writeErr(new String(buf).getBytes("UTF-8")); // this could perhaps be made faster, avoiding the string allocation, but it's not an issue for now
							}
						}
						
						while (stdoutStream.ready()) {
							if (!sendToREPL) {
								var newMessage = stdoutStream.readLine();
						
								if(!newMessage.startsWith("!<*")) { // special sequence for sending messages to this plugin, rather than the user
									p.logMessage("angr [" + scriptName + "]", newMessage);
								} else {
									if (newMessage.contains("show_repl")) {
										p.logMessage("Entering REPL...");
										
										p.statusReport(""); // when moving to the repl, clear the status report
										
										// show the fancy repl window and pass responsibility for displaying output over to it
										if (replProvider == null) {
											replProvider = new AngrREPL(stdinStream, p.getTool());
										} else {
											replProvider.iconsole.show();
										}
										stdinStream.write("READY\n");
										sendToREPL = true;
										p.onREPLStart(); // notify anything that cares that the repl has opened 
									} else if (newMessage.contains("progress_report")) {
										p.statusReport(newMessage.replaceFirst("^\\!\\<\\* progress_report", ""));
									}
								}
							} else {
								char[] buf = new char[2000];
								stdoutStream.read(buf);
								var strBuf = new String(buf);
								if (strBuf.contains("!<* exit_repl")) {
									stdinStream.write("READY\n");
									sendToREPL = false;
									p.onREPLEnd();
								}
								replProvider.write(strBuf.getBytes("UTF-8"));
							}
						}

					}
					
					String lines = null;
					
					try {
						stdoutStream.reset(); // rewind the stream back to the mark#
						lines = stdoutStream.lines().reduce("", (a,b) -> a+b); // concat each line
					} catch (IOException e) {
						// the mark is invalid, too much output! just set lines to the empty string
						lines = "";
					}
					
					if (replProvider != null) {
						replProvider.cleanup();
					}
					
					return lines;
				} catch (InterruptedException e) { // if some OS process suspends the python process, or more likely the user clicked the stop button.
					// kill the angr process, then gracefully return
					p.logMessage("KILLING ANGR");
					this.scriptProcess.destroy();
					if (replProvider != null) {
						replProvider.cleanup();
					}
					return null;
				} catch (IOException e) {
					Msg.showError(this, null, "Failed to read from script?", e);
				}
				if (replProvider != null) {
					replProvider.cleanup();
				}
				return null;
			}
			
			// called when doInBackground returns, executed in the main plugin's thread
			@Override
			protected void done() {			
				try {
					onDone.accept(get()); // Invoke the end-of-script callback (get() cannot block in done())
				} 
				catch (InterruptedException ignore) {} // already handled internally
				catch (ExecutionException ignore) {} // should never occur because by the time done() is run, it should have a result ready
				catch (CancellationException ignore) {} // the function was cancelled earlier, that's okay.
			}
			
			
		};
		
		scriptWorker.execute();
		runningWorkers.add(scriptWorker);
		return;
	}
	
	/**
	 * Instructs each worker thread to break the currently running script, which just sends BREAK down stdin. 
	 * It's up to the script what, if anything, it does with that. In angr_main, this will trigger a halt of simulation and a REPL entry.
	 */
	public void doBreak() {
		for (var worker : runningWorkers) {
			worker.brk();
		}
	}
	
	/**
	 * Kills <em>ALL<em> running worker threads. 
	 */
	public void stopScripts() {
		for (var worker : runningWorkers) {
			worker.cancel(true);
		}
		
		runningWorkers.clear();
	}
	
	/**
	 * Runs a python script, blocking until completion.
	 * @param scriptName The name of the script to run
	 * @param pypath The path to the python executable
	 * @return The stdout of the script
	 */
	private String startScriptBlocking(String scriptName, Path pypath) {
		String[] noArgs = {};
		
		var scriptProcess = AngrInterface.getScriptProcess("get_angr_version", pypath, noArgs);
		if (scriptProcess == null) {
			return null;
		}
		
		try {
			scriptProcess.waitFor();
			return new String(scriptProcess.getInputStream().readAllBytes());
		} catch (InterruptedException e) {
			Msg.showError(AngrInterface.class, null, "Failed to wait for script?", e);
		} catch (IOException e) {
			Msg.showError(AngrInterface.class, null, "Failed to read from script?", e);
		}
		return null;	
	}
	
	/**
	 * Constructs and starts a given script, with args array, using the specified version of python.
	 * Python will be started with the -u flag, meaning it won't be buffered on python's side.
	 * 
	 * If something goes wrong, null will be returned and a message will be presented to the user
	 * 
	 * NOTE: the args array cannot be used to pass arguments to python itself.
	 * @param scriptName The name of the script to run (without the .py extension)
	 * @param pypath The path to the python executable
	 * @param args An array of arguments to be passed to the script
	 * @return the now-running Process
	 */
	private static Process getScriptProcess(String scriptName, Path pypath, String[] args) {
		try {
			ResourceFile script = Application.getModuleDataFile("angrscripts/" + scriptName + ".py");
			File scriptFile = script.getFile(true);
			
			ArrayList<String> argsArray = new ArrayList<String>();
			argsArray.add(pypath.toString());
			argsArray.add("-u"); // Disable python buffering - it's occuring on the java side, no need for python to do it too
			argsArray.add(scriptFile.getAbsolutePath());
			
			for (var arg : args) {
				argsArray.add(arg);
			}
			
			ProcessBuilder builder = new ProcessBuilder(argsArray);
			return builder.start();
		} catch (FileNotFoundException e) {
			Msg.showError(AngrInterface.class, null, "Failed to locate script!", "Script "+ scriptName +" not found! \n" + e.toString());
			return null;
		} catch (IOException e) {
			Msg.showError(AngrInterface.class, null, "Failed to start script!", "Script "+ scriptName +" failed to start: \n" + e.toString());
			return null;
		}
	}
	
	public class AngrException extends RuntimeException {
		public AngrException(String message) {
			super(message);
		}
	}

	/**
	 * Invoke the main angr script
	 * 
	 * Writes the passed configuration to a temporary file, and then starts angr_main with that file as a parameter.
	 * When angr terminates, attempts to delete the file.
	 * 
	 * Note: under certain configurations, the config file could contain raw python code that will be evaluated by the script.
	 * Right now, the script makes no secuirty guarantees, but if this were ever to change, then a race condition could occur where
	 * something could write to the file before the python side reads it.
	 * 
	 * @param config the angr configuration to use
	 */
	public void runAngrMain(AngrConfiguration config) {
		this.p.logMessage("Starting angr...");
		
		// Write the config to a json file, that will be read back by the main angr script.
		var tempDir = Application.getUserTempDirectory().toPath();
		var configFile = Paths.get(tempDir.toString(), "angrConfig"+ System.currentTimeMillis() +".json");  // disambiguate config files in the weird case where one or more users on the same machine are using this plugin
		
		try {
			Files.write(configFile, config.toJson(p.getCurrentProgram()).getBytes(), StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
			String[] args = { configFile.toString() };
			startScript("angr_main", (output) -> {
				this.p.logMessage("angr stopped.");
				p.provider.angrFinished();
				p.angrIsRunning = false;
				// Once the script is done, clean up the temp file
				try {
					Files.delete(configFile);
				} catch (IOException e) {
					Msg.warn(this, "Failed to remove temporary file!", e);
				}  // It doesn't really matter too much if the temp file sticks around for some reason
				
			}, args, Paths.get(config.breakPath));
		} catch (IOException e) {
			Msg.showError(this, null, "Failed to start angr!", "Could not create file for angr config: " + e.toString());
		}
		
		
	}


}
