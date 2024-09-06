package angrintegration;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import angrintegration.entrypoint.EntryPoint.BlankState;
import angrintegration.entrypoint.EntryPoint.CallState;
import angrintegration.exploregoal.ExploreGoal.AddressGoal;
import angrintegration.symbolic.Hook.InlineHook;
import angrintegration.symbolic.Hook.SimProcedureHook;
import docking.widgets.fieldpanel.field.AttributedString;
import docking.widgets.fieldpanel.field.TextFieldElement;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.theme.GColor;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.app.util.viewer.field.ListingTextField;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.proxy.CodeUnitProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

// will be automatically found by Ghidra, since the class name ends in FieldFactory.
public class AngrInfoFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "angr information";
	
	// KLUDGE: inside getField, there's no way to get a PluginTool and therefore get an instance of the plugin normally.
	// AngrIntegrationPlugin will add itself to this map on construction, and then getFieldLocation will try and find plugins that correspond to the Program
	// that the code unit being examined is from.
	// A map because if there are multiple instances of a Tool open, there will be multiple separate Plugin instances for each. Of course, normally there would 
	// similarly be matching FieldFactorys for each, but this is static.
	// The keys of the map are FormatManagers, a class which has little relevance other than being unique per Tool instance, so can be used ot ensure the correct
	// plugin instance for the Tool containing this FieldFactory is found.
	public static Map<FormatManager, AngrIntegrationPlugin> plugins = new HashMap<FormatManager, AngrIntegrationPlugin>();
	
	public AngrInfoFieldFactory() {
		super(FIELD_NAME);
	}
	
	protected AngrInfoFieldFactory(String name, FieldFormatModel formatModel, ListingHighlightProvider highlightProvider, ToolOptions options, ToolOptions fieldOptions) {
		super(name, formatModel, highlightProvider, options, fieldOptions);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, ListingHighlightProvider highlightProvider,
			ToolOptions options, ToolOptions fieldOptions) {
		Msg.info(this, "HIT newInstance");
		return new AngrInfoFieldFactory(name, formatModel, highlightProvider, options, fieldOptions);
	}

	@Override
	public ListingField getField(ProxyObj<?> obj, int varWidth) {
		
		if (!(obj instanceof CodeUnitProxy)) {
			return null;
		}
		
		var cu = ((CodeUnitProxy) obj).getObject(); // safe due to acceptsType() semantics
		
		
		var plugin = plugins.getOrDefault(getFieldModel().getFormatManager(), null);
		if (plugin == null) {
			return null; // if the plugin isn't loaded, but somehow this is, do nothing.
		}
		
		var addr = cu.getAddress();
		var textElements = new ArrayList<TextFieldElement>();
		
		// get the configuration object from the plugin
		// NOTE: if performance ever becomes problematic, perhaps rework how this is done. this is potentially expensive!
		var config = plugin.provider.makeConfiguration();
		
		for (var abstractHook : config.hooks) {
			if (!abstractHook.enabled) {
				continue;  // skip disabled hooks
			}
			
			if (abstractHook instanceof InlineHook) {
				var hook = (InlineHook) abstractHook;
				if (hook.length == 0 && addr.equals(hook.target)) {
					textElements.add(new TextFieldElement(new AttributedString("HOOK " + hook.toString() , new GColor("color.palette.lightpurple"), getMetrics()), 0, 0));
				} else if (addr.equals(hook.target)) {
					textElements.add(new TextFieldElement(new AttributedString("┌ HOOK " + hook.toString() , new GColor("color.palette.lightpurple"), getMetrics()), 0, 0));
				}
				
				try {
					var range = new AddressRangeImpl(hook.target, hook.length);
					if (range.contains(addr) && !range.getMinAddress().equals(addr) && !range.getMaxAddress().equals(cu.getMaxAddress())) {
						textElements.add(new TextFieldElement(new AttributedString("│ ", new GColor("color.palette.lightpurple"), getMetrics()), 0, 0));
					}
					
					if (cu.getMaxAddress().equals(range.getMaxAddress()) && hook.length != 0) {
						textElements.add(new TextFieldElement(new AttributedString("└ END " + hook.toString(), new GColor("color.palette.lightpurple"), getMetrics()), 0, 0));
					}
				} catch (AddressOverflowException ignored) {}
				
			} else if (abstractHook instanceof SimProcedureHook) {
				var hook = (SimProcedureHook) abstractHook;
				if (hook.target.equals(addr)) {
					textElements.add(new TextFieldElement(new AttributedString("HOOK " + hook.toString(), new GColor("color.palette.purple"), getMetrics()), 0, 0));
				}
			}
		}
		
		if (config.avoidAddrs.contains(addr)) {
			textElements.add(new TextFieldElement(new AttributedString("AVOID ", new GColor("color.palette.red"), getMetrics()), 0, 0));
		}
		
		if ((config.entryPoint instanceof BlankState && ((BlankState) config.entryPoint).addr.equals(addr)) || 
				(config.entryPoint instanceof CallState && ((CallState) config.entryPoint).addr.equals(addr))) {
			textElements.add(new TextFieldElement(new AttributedString("ENTRY ", new GColor("color.palette.green"), getMetrics()), 0, 0));
		}
		
		if (config.exploreCondition instanceof AddressGoal && ((AddressGoal) config.exploreCondition).addresses.contains(addr)) {
			textElements.add(new TextFieldElement(new AttributedString("TARGET ", new GColor("color.palette.darkorange"), getMetrics()), 0, 0));
		}
		
		if (textElements.size() == 0) {
			return null;
		}

		return ListingTextField.createPackedTextField(this, obj, textElements.toArray(new TextFieldElement[0]), startX, width, 5, hlProvider);
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum, ProgramLocation loc) {
		return null; // unsure what this does, but leaving it null doesn't cause any issues
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		return null; // unsure what this does, but leaving it null doesn't cause any issues
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return true; // proxyObjectClass.equals(CodeUnit.class); // don't care what the field is, as long as it corresponds with a memory location, which it will
	}

}
