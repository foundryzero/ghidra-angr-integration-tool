package angrintegration.entrypoint;

import java.util.ArrayList;
import java.util.List;

import angrintegration.symbolic.SymbolicField;
import ghidra.program.model.address.Address;

/**
 * Represents an EntryPoint.
 * 
 * Sealed because this must exactly correspond with EntryPoint types defined in angr_scripts/angrMain.py
 */
public sealed interface EntryPoint {

	/**
	 * Get a name for the EntryPoint, suitable for use in UI.
	 * @return a display name for the EntryPoint
	 */
	public String getDisplayName();
	
	public default String getName() {
		return this.getClass().getSimpleName();
	}
	
	
	/**
	 * A blank state, with no constraints other than a single entry point address.
	 */
	public static final class BlankState implements EntryPoint {
		
		public Address addr;
		
		public BlankState(Address addr) {
			this.addr=addr;
		} 
		
		@Override
		public String getDisplayName() {
			return "Blank State";
		}
	}
	
	/**
	 * A state ready to start execution at main() or equivalent of the program.
	 */
	public static final class EntryState implements EntryPoint {
		@Override
		public String getDisplayName() {
			return "Entry State";
		}
	}
	
	/**
	 * A state ready to execute a function call at a specific address.
	 */
	public static final class CallState implements EntryPoint {
		
		public Address addr;
		public Address stackBase;

		public String signature;
		public List<SymbolicField> params;
		

		public CallState(Address addr) {
			this.addr = addr;
			this.params = new ArrayList<SymbolicField>();
		} 
		@Override
		public String getDisplayName() {
			return "Call State";
		}
	}
	
	/**
	 * A state that runs through any initalizers before hitting the main entry point.
	 */
	public static final class FullInitState implements EntryPoint {
		@Override
		public String getDisplayName() {
			return "Full Init State";
		}
	}
}

