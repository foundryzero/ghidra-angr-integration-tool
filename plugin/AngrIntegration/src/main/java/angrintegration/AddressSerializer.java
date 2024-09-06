package angrintegration;

import java.lang.reflect.Type;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;

/**
 * A simple serializer that writes a ghidra Address as a BigInteger.
 * 
 * Note: Only supports addresses from the default address space, and will assume addresses come from that space when deserializing.
 */
public class AddressSerializer implements JsonSerializer<Address>, JsonDeserializer<Address> {
	
	AddressFactory factory;
	
	public AddressSerializer(Program currentProgram) {
		if (currentProgram != null) {
			this.factory = currentProgram.getAddressFactory();
		} else {
			this.factory = null;
		}
	}

	@Override
	public JsonElement serialize(Address src, Type typeOfSrc, JsonSerializationContext context) {
		if (factory != null && !src.getAddressSpace().equals(factory.getDefaultAddressSpace())) {
			throw new IllegalArgumentException("Tried to serialize an address from a space that is not the default! " +  src.getAddressSpace().toString());
		}
		return new JsonPrimitive(src.getOffsetAsBigInteger());
	}

	@Override
	public Address deserialize(JsonElement src, Type typeOfSrc, JsonDeserializationContext context) throws JsonParseException {
		if (factory == null) {
			throw new JsonParseException("Must provide a program when deserializing!");
		}
		
		var zeroAddr = factory.getDefaultAddressSpace().getMinAddress();
		
		try {
			return zeroAddr.addNoWrap(src.getAsBigInteger());
		} catch (AddressOverflowException e) {
			throw new JsonParseException("Failed to create address: Too large for space!", e);
		}
		
	}
}