package angrintegration.symbolic;

import java.lang.reflect.Type;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;

/**
 * Represents a Constraint object. code should be a python expression that will evaluate to a claripy Bool representing
 * the constriant. It may use several special functions for conveinence -- see data/angr_scripts/symbolic_field.py for
 * full details.
 */
public record ConstraintEntry(String code) {
	public ConstraintEntry(ConstraintEntry other) {
		this(other.code);
	}
	
	public static class ConstraintEntryDeserializer implements JsonDeserializer<ConstraintEntry> {
		@Override
		public ConstraintEntry deserialize(JsonElement src, Type typeOfSrc, JsonDeserializationContext context)
				throws JsonParseException {
			return new ConstraintEntry(src.getAsJsonObject().get("code").getAsString());
		}
		
	}
}
