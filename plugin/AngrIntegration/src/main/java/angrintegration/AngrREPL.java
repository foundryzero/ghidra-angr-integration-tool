package angrintegration;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import docking.Tool;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterComponentProvider;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.util.Msg;
import resources.Icons;

/**
 * Glue between a AngrInterface and an InterpreterPanel, forwarding input down the angrStdin pipe and displaying any output it's sent.
 */
public class AngrREPL { 

	OutputStreamWriter angrStdin;
	
	Tool pluginTool;
	
	InterpreterComponentProvider iconsole;

	public AngrREPL(OutputStreamWriter output, Tool pluginTool) {
		this.angrStdin = output;
		this.pluginTool = pluginTool;
		
		var ipserv = pluginTool.getService(InterpreterPanelService.class);
		
		// This cast is mildly dangerous, because it's theoretically possible for some non-default InterpreterPanelService to return
		// something that isn't a ComponentProvider :( but it's nessecary, because the component needs to be removed when cleanup() is called.
		iconsole = (InterpreterComponentProvider) ipserv.createInterpreterPanel(new InterpreterConnection() {
			@Override
			public String getTitle() {
				return "angr - Python 3"; // explicitly say python 3 because Ghidra users will be familiar with python interpreters being python 2
			}
		
			@Override
			public Icon getIcon() {
				return Icons.SAVE_ICON;
			}
			
			@Override
			public List<CodeCompletion> getCompletions(String cmd) {
				return new ArrayList<CodeCompletion>();
			}
		}, true);

	}

	/**
	 * Write some bytes to the underlying console.
	 * @param b the bytes to write
	 */
	public void write(byte[] b) {
		try {
			iconsole.getStdOut().write(b);
		} catch (IOException ex) {
			Msg.showError(this, null, "Failed to write to console!", ex);
		}
	}
	

	/**
	 * Write some bytes to the underlying console (but in red).
	 * @param b the bytes to write
	 */
	public void writeErr(byte[] b) {
		try {
			iconsole.getStdErr().write(b);
		} catch (IOException ex) {
			Msg.showError(this, null, "Failed to write to console!", ex);
		}
	}
	
	/**
	 * Check if the console has any input waiting, and if so, forward it down the supplied stream.
	 * Should be called frequently by the worker thread orchestrating the angr process.
	 */
	public void checkSendInput() {
		var input = iconsole.getStdin();
		try {
			while (input.available() > 0) {
				angrStdin.write(input.read());
			}
			angrStdin.flush();
		} catch (IOException e) {
			Msg.error(this, e);
		}
	}
	
	/**
	 * Delete the interpreter, now that angr has finished.
	 */
	public void cleanup() {
		iconsole.removeFromTool();
	}

}
