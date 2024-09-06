package angrintegration.symbolic;

import java.lang.reflect.Type;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;

/**
 * Represents a field containing a value that may be symbolic. 
 * @param code Python code that will be passed to eval() to create the symbolic variable
 * @param width The width of the created symbolic field
 */
public record SymbolicField(String code, int width, String name, String originalName) {
	
	/**
	 * The Gson version Ghidra ships with (2.9.0) doesn't support record classes, so this has to do it instead.
	 * 2.10.0 _does_, so if Ghidra ever updates this can be removed.
	 */
	public static class SymbolicFieldDeserializer implements JsonDeserializer<SymbolicField> {
		@Override
		public SymbolicField deserialize(JsonElement src, Type typeOfSrc, JsonDeserializationContext context)
				throws JsonParseException {
			
			var obj = src.getAsJsonObject();
			
			var code = obj.get("code").getAsString();
			var width = obj.get("width").getAsInt();
			var name = obj.get("name").getAsString();
			var originalName = obj.get("originalName").getAsString();
			
			return new SymbolicField(code, width, name, originalName);
		}
	}
	
}
