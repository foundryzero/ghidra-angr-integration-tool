package angrintegration.symbolic;

import java.lang.reflect.Type;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;

public record VariableEntry(String loc, String name, int width, String value) {
	public Object getByIndex(int idx) {
		switch (idx) {
		case 0: 
			return this.loc;
		case 1: 
			return this.name;
		case 2:
			return this.width;
		case 3:
			return this.value;
		default:
			throw new IllegalArgumentException("Unexpected value: " + idx);
		}
	}
	
	public VariableEntry setByIndex(Object newVal, int idx) {
		switch (idx) {
		case 0:
			return new VariableEntry((String) newVal, name, width, value);
		case 1:
			return new VariableEntry(loc, (String) newVal, width, value);
		case 2:
			return new VariableEntry(loc, name, (int) newVal, value);
		case 3:
			return new VariableEntry(loc, name, width, (String) newVal);
		default:
			throw new IllegalArgumentException("Unexpected value: " + idx);
		}
	}
	
	/**
	 * Copy constructor
	 * @param other the VariableEntry to create a copy of
	 */
	public VariableEntry(VariableEntry other) {
		this(other.loc, other.name, other.width, other.value);
	}
	
	public static class VariableEntryDeserializer implements JsonDeserializer<VariableEntry> {
		@Override
		public VariableEntry deserialize(JsonElement src, Type typeOfSrc, JsonDeserializationContext context)
				throws JsonParseException {
			
			var obj = src.getAsJsonObject();
			
			var loc = obj.get("loc").getAsString();
			var name = obj.get("name").getAsString();
			var width = obj.get("width").getAsInt();
			var value = obj.get("value").getAsString();
			
			return new VariableEntry(loc, name, width, value);
		}
		
	}
}