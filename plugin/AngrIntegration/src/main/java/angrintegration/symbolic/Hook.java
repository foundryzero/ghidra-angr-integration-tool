package angrintegration.symbolic;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;

import ghidra.program.model.address.Address;

/**
 * Represents a complete Hook as part of an AngrConfiguration.
 */
public abstract class Hook {
	
	public boolean enabled;
	
	private String name;
	
	public Address target;
	
	public List<ConstraintEntry> constraints = new ArrayList<ConstraintEntry>();
	public List<VariableEntry> variables = new ArrayList<VariableEntry>();
	public String customCode;
	
	public Hook(Address target) {
		this.target = target;
		this.name = "";
		this.customCode = "";
		this.enabled = true;
	}
	
	/**
	 * An InlineHook is a hook that happens at a certain memory location, and skips over a certain number of addresses when it finishes execution
	 */
	public static class InlineHook extends Hook {
		public InlineHook(Address target) {
			super(target);
		}

		public int length;
		
		@Override
		public String getDefaultName() {
			return "Inline " + super.getDefaultName();
		}
	}

	/**
	 * A SimProcedureHook replaces a whole procedure, parsing it's arguments and having the ability to return values back to the simulated program.
	 */
	public static class SimProcedureHook extends Hook {
		public SimProcedureHook(Address target) {
			super(target);
		}

		public String signature;
		
		@Override
		public String getDefaultName() {
			return "SimProcedure " + super.getDefaultName();
		}
	}
	
	@Override
	public String toString() {
		if (!this.name.isBlank()) {
			return name;
		}
		return this.getDefaultName();
	}
	
	/**
	 * Get a reasonable default name for the hook, based on the address and type.
	 * @return The generated name as a string
	 */
	protected String getDefaultName() {
		var suffix = "";
		if (target != null) {
			suffix = "@" + target.toString();
		}

		return "Hook" + suffix;
	}
	
	public String getName() {
		return this.name;
	}
	
	public void setName(String newName) {
		this.name = newName;
	}
	
	
	public static class HookDeserializer implements JsonDeserializer<Hook> {
		@Override
		public Hook deserialize(JsonElement src, Type typeOfSrc, JsonDeserializationContext context)
				throws JsonParseException {
			var obj = src.getAsJsonObject();
			
			if (obj.has("length")) {
				return context.deserialize(src, InlineHook.class);
			}
			return context.deserialize(src, SimProcedureHook.class);
		}
		
	}
}
