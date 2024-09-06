package angrintegration.entrypoint;

import java.lang.reflect.Type;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;



/**
 * A serializer module for EntryPoints that also inserts the class name as an element, which wouldn't be pushed otherwise.
 */
public class EntryPointSerializer implements JsonSerializer<EntryPoint>, JsonDeserializer<EntryPoint> {
	
	public static final Class<?>[] ENTRY_POINT_TYPES = {EntryPoint.EntryState.class, EntryPoint.BlankState.class, EntryPoint.CallState.class, EntryPoint.FullInitState.class};
	
	@Override
	public JsonElement serialize(EntryPoint src, Type typeOfSrc, JsonSerializationContext context) {
		var element = context.serialize(src).getAsJsonObject();
		element.add("type", context.serialize(src.getName()));
		return element;
	}

	@Override
	public EntryPoint deserialize(JsonElement src, Type typeOfSrc, JsonDeserializationContext context)
			throws JsonParseException {		
		var src_obj = src.getAsJsonObject();
		src_obj.get("type").getAsString();
		
		Class<?> foundClass= null;
		
		for (var clazz : ENTRY_POINT_TYPES) {
			if (clazz.getSimpleName().equals(src_obj.get("type").getAsString())) {
				foundClass = clazz;
			}
		}
		
		if (foundClass == null) {
			throw new JsonParseException("Failed to understand this type of EntryPoint!");
		}
		
		// remove the type field because that won't be what gson expects
		src_obj.remove("type");
		
		return context.deserialize(src_obj, foundClass);
	}
}