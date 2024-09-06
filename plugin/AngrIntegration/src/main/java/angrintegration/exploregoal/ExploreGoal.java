package angrintegration.exploregoal;

import java.lang.reflect.Type;
import java.util.List;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import ghidra.program.model.address.Address;

/**
 * Represents an ExploreGoal.
 * 
 * Sealed because this must exactly correspond with ExploreGoal types defined in angr_scripts/angrMain.py
 */
public sealed interface ExploreGoal {
	
	/**
	 * Get a name for the ExploreGoal, suitable for use in UI.
	 * @return a display name for the ExploreGoal
	 */
	public String getDisplayName();
	
	public default String getName() {
		return this.getClass().getSimpleName();
	}
	
	/**
	 * An ExploreGoal that triggers when one of a list of addresses has been reached.
	 */
	public static final class AddressGoal implements ExploreGoal {
		
		public List<Address> addresses;
		
		public AddressGoal(List<Address> addresses) {
			this.addresses = addresses;
		}
		
		@Override
		public String getDisplayName() {
			return "Target Address";
		}
	}
	
	/**
	 * An ExploreGoal that triggers when all execution has terminated.
	 */
	public static final class TerminationGoal implements ExploreGoal {
		@Override
		public String getDisplayName() {
			return "Termination";
		}
	}
	
	/**
	 * An ExploreGoal that triggers when the instruction pointer becomes symbolic (in a way where there are >= 256 possible concrete values). 
	 */
	public static final class UnconstrainedGoal implements ExploreGoal {
		
		public Address target;
		
		public UnconstrainedGoal(Address target) {
			this.target = target;
		}
		
		@Override
		public String getDisplayName() {
			return "Unconstrained PC";
		}
	}
	
	/**
	 * An ExploreGoal that triggers when a provided python function returns True.
	 */
	public static final class CustomGoal implements ExploreGoal {
		
		public String code = "";
		
		public CustomGoal(String code) {
			this.code = code;
		}
		
		@Override
		public String getDisplayName() {
			return "Custom";
		}
	}
	
	
	/**
	 * A serializer module for ExplreGoals that also inserts the class name as an element, which wouldn't be pushed otherwise.
	 */
	public class ExploreGoalSerializer implements JsonSerializer<ExploreGoal>, JsonDeserializer<ExploreGoal> {
		private static final Class<?>[] EXPLORE_GOAL_TYPES = {
				TerminationGoal.class,
				AddressGoal.class,
				UnconstrainedGoal.class,
				CustomGoal.class,
		};

		
		@Override
		public JsonElement serialize(ExploreGoal src, Type typeOfSrc, JsonSerializationContext context) {
			var element = context.serialize(src).getAsJsonObject();
			element.add("type", context.serialize(src.getName()));
			return element;
		}
		
		@Override
		public ExploreGoal deserialize(JsonElement src, Type typeOfSrc, JsonDeserializationContext context)
				throws JsonParseException {		
			var src_obj = src.getAsJsonObject();
			src_obj.get("type").getAsString();
			
			Class<?> foundClass= null;
			
			for (var clazz : EXPLORE_GOAL_TYPES) {
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
}