package angrintegration;

import java.util.List;

import com.google.gson.GsonBuilder;
import com.google.gson.stream.JsonReader;

import angrintegration.entrypoint.EntryPoint;
import angrintegration.entrypoint.EntryPointSerializer;
import angrintegration.exploregoal.ExploreGoal;
import angrintegration.symbolic.ConstraintEntry;
import angrintegration.symbolic.Hook;
import angrintegration.symbolic.SymbolicField;
import angrintegration.symbolic.VariableEntry;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Represents the configuration needed for a complete run of angr
 * 
 * When angr is invoked, this gets serialized and written to a temporary file, which the main angr script then reads.
 */
public class AngrConfiguration {
	
	/**
	 * The absolute path to the binary being analysed.
	 */
	public String binaryPath;
	
	/**
	 * The name of the architecture file to find. A corresponding file with the <code>.py</code> extension should exist 
	 * in the `architectureSpecPath` directory.
	 */
	public String architectureName;
	
	/**
	 * The directory to find architecture files.
	 */
	public String architectureSpecPath;

	/**
	 * True if angr should attempt to load external libraries when loading the main binary. 
	 */
	public boolean loadExternalLibraries;
	
	/**
	 * The entry point that angr will use to create a starting SimState.
	 */
	public EntryPoint entryPoint;
	
	/**
	 * Specifies in some way when to stop symbolic execution.
	 */
	public ExploreGoal exploreCondition;
	
	/**
	 * The base address of the binary being loaded into memory. Should match what Ghidra is using, or things will go wrong.
	 */
	public Address baseAddr;
	
	/**
	 * A list of addresses that should not be symbolically simulated. If execution reaches there, the state will be placed into
	 * the <code>avoid</code> stash and will not be further explored.
	 */
	public List<Address> avoidAddrs;
	
	/**
	 * True if the angr process starts a repl once it's completed.
	 */
	public boolean repl;
	
	/**
	 * True if the angr process should print details of every user-defined variable when done
	 */
	public boolean showDetails;
	
	/**
	 * A list of symbolic variables to setup and bind to registers or memory on startup.
	 */
	public List<VariableEntry> symbolicVariables;
	
	/**
	 * A list of constraints to apply at startup.
	 */
	public List<ConstraintEntry> constraints;
	
	/**
	 * A list of Hooks to apply to the program, which will cause new variables or constraints to be created, or custom code to be run, at certain program locations.
	 */
	public List<Hook> hooks;

	/**
	 * A file to write to when the break key is pressed, as a poor man's IPC to the angr process.
	 * (Ideally stdin or a signal would be used, but both are nigh-impossible on windows)
	 */
	public String breakPath;
	
	/**
	 * Defines the behavior of angr when reading from uninitialized memory.
	 * 
	 * <ul>
	 * <li> <b>NONE</b> - warn and fill with symbolic variables
	 * <li> <b>FILL_ZERO</b> - always return 0 for any uninitialized reads
	 * <li> <b>FILL_UNCONSRTAINED</b> - always return a symbolic variable for any uninitialized reads
	 * </ul>
	 */
	public MemoryAccessPolicy memoryAccessPolicy;
	
	/**
	 * Defines the behavior of angr when reading from uninitialized registers.
	 * 
	 * <ul>
	 * <li> <b>NONE</b> - warn and fill with symbolic variables
	 * <li> <b>FILL_ZERO</b> - always return 0 for any uninitialized reads
	 * <li> <b>FILL_UNCONSRTAINED</b> - always return a symbolic variable for any uninitialized reads
	 * </ul>
	 */
	public MemoryAccessPolicy registerAccessPolicy;
	
	/**
	 * A section of python code run when simulation ends, to complement the standard output of state data.
	 */
	public String codeWhenDone;
	
	public AngrConfiguration() {} 
	
	/**
	 * Serializes the AngrConfiguration using gson.
	 * @return a JSON representation of the object
	 */
	public String toJson(Program currentProgram) {
		var gson = new GsonBuilder();
		gson.registerTypeAdapter(Address.class, new AddressSerializer(currentProgram));
		gson.registerTypeAdapter(EntryPoint.class, new EntryPointSerializer());
		gson.registerTypeAdapter(ExploreGoal.class, new ExploreGoal.ExploreGoalSerializer());
		return gson.create().toJson(this);
	}
	
	@Override
	public String toString() { 	
		return this.toJson(null);
	}

	public static AngrConfiguration from(JsonReader reader, Program currentProgram) {
		var gson = new GsonBuilder();
		gson.registerTypeAdapter(Address.class, new AddressSerializer(currentProgram));
		gson.registerTypeAdapter(EntryPoint.class, new EntryPointSerializer());
		gson.registerTypeAdapter(ExploreGoal.class, new ExploreGoal.ExploreGoalSerializer());
		gson.registerTypeAdapter(SymbolicField.class, new SymbolicField.SymbolicFieldDeserializer());
		gson.registerTypeAdapter(VariableEntry.class, new VariableEntry.VariableEntryDeserializer());
		gson.registerTypeAdapter(ConstraintEntry.class, new ConstraintEntry.ConstraintEntryDeserializer());
		gson.registerTypeAdapter(Hook.class, new Hook.HookDeserializer());
		return gson.create().fromJson(reader, AngrConfiguration.class);
	}
	
	public static enum MemoryAccessPolicy {
		NONE,
		FILL_ZERO,
		FILL_UNCONSTRAINED;
		
		@Override
		public String toString() {
			switch (this) {
			case NONE: {
				return "Warn, and fill with unconstrained symbolic variables";
			}
			case FILL_ZERO: {
				return "Fill with zero";
			}
			case FILL_UNCONSTRAINED: {
				return "Fill with unconstrained symbolic variables";
			}
			default: {
				throw new IllegalArgumentException("Unknown MemoryAccessPolicy");
			}
			}
		}
	}
	
}
