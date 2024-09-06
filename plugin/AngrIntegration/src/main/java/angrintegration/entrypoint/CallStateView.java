package angrintegration.entrypoint;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import angrintegration.symbolic.SymbolicField;
import angrintegration.symbolic.SymbolicFieldView;
import docking.widgets.button.GButton;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.HintTextField;
import docking.widgets.textfield.IntegerTextField;
import generic.theme.GIcon;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.layout.PairLayout;

/**
 * EntryPointView handling a CallState.
 * 
 * Provides options for the function address and signature, and will autofill the 
 * signature from the current program.
 * 
 */
public class CallStateView extends EntryPointView {

	private JPanel panel;
	private IntegerTextField addressField;
	private HintTextField signatureField;
	private IntegerTextField stackBaseField;
	
	public CodeViewerService codeViewerService;
	
	private Map<String, SymbolicFieldView> parameters;
	
	// null if the current signature has been customised or never correpsonded to a Ghidra function to begin with.
	private Function maybeFunc;
	
	// true only when signatureField is being written to as the result of a signature lookup due to address being changed.
	private boolean isChangingFunc;
	
	// A reference to the currently loaded program, used to get function signatures
	private Program currentProgram;
		
	public CallStateView(Program p) {
		maybeFunc = null;
		currentProgram = p;
		isChangingFunc = false;
		
		// LinkedHashMap is insertion ordered, and this behavior is relied upon.
		parameters = new LinkedHashMap<String, SymbolicFieldView>();
		
		panel = new JPanel(new PairLayout(5,5));
		
		panel.add(new GLabel("Address:"));
		addressField = new IntegerTextField();
		addressField.getComponent().setToolTipText("The address of the function to load");
		
		codeViewerService = null;
		
		var syncAddressButton = new GButton(new GIcon("icon.navigate.in"));
		syncAddressButton.setToolTipText("Synchronize with listing window");
		syncAddressButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				addressField.setText("0x" + codeViewerService
									.getCurrentLocation()
									.getAddress()
									.getOffsetAsBigInteger()
									.toString(16));
			}
		});
		
		var addressPanel = new JPanel(new BorderLayout());
		addressPanel.add(addressField.getComponent(), BorderLayout.CENTER);
		addressPanel.add(syncAddressButton, BorderLayout.LINE_END);
		
		panel.add(addressPanel);
		
		addressField.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				BigInteger addr_int = addressField.getValue();
				var factory = currentProgram.getAddressFactory();
				if (addr_int != null) {
					
					var addr = factory.getAddress(addr_int.toString(16));
					
					maybeFunc = currentProgram.getFunctionManager().getFunctionAt(addr);
					
					if (maybeFunc != null) {
						isChangingFunc = true;
						signatureField.setText(maybeFunc.getPrototypeString(true, false));
						isChangingFunc = false;
					}
					
				}
				
				codeViewerService.getListingPanel().updateDisplay(false); 
			}
		});
		
		
		panel.add(new GLabel("Stack Base:"));
		stackBaseField = new IntegerTextField();
		stackBaseField.setText("0x0500");
		stackBaseField.getComponent().setToolTipText("The base of the synthetic stack angr will create to execute the function");
		panel.add(stackBaseField.getComponent());
		
		panel.add(new GLabel("Signature:"));
		signatureField = new HintTextField("void myFunction(...);");
		signatureField.setToolTipText("The signature of the function being called (in C syntax) Note: undefined is not a type!");
		signatureField.getDocument().addDocumentListener(new DocumentListener() {

			@Override
			public void insertUpdate(DocumentEvent e) {
				refreshParamFields();
			}

			// Glue the other two events to insertUpdate
			
			@Override
			public void removeUpdate(DocumentEvent e) {
				this.insertUpdate(e);
			}
			
			
			@Override
			public void changedUpdate(DocumentEvent e) {
				this.insertUpdate(e);
			}
		});
		panel.add(signatureField);
	}
	
	/**
	 * Create and destroy text fields to match the function signature written in the signatureField, whilst attempting to preserve the contents of 
	 * any already filled fields.
	 */
	private void refreshParamFields() {
		FunctionSignature sig = null;
		if (isChangingFunc) {
			sig = maybeFunc.getSignature();
		} else {
			maybeFunc = null; // if the signature field has been written to outside of a address change, invalidate the stored function
			
			var sigParser = new FunctionSignatureParser(currentProgram.getDataTypeManager(), null);
			try {
				sig = sigParser.parse(null, signatureField.getText());
			} catch (CancelledException | ParseException e1) {
				return; // only update the params fields if there's actually a valid signature here.
			}
		}
		
		Arrays.stream(panel.getComponents())
			.dropWhile(x -> x != signatureField)
			.skip(1)
			.forEach(x -> panel.remove(x));
		
		
		// build a map from param names to values, to restore existing values after the components have been rebuilt
		var tempParamValues = new HashMap<String, String>();
		parameters.forEach((n,c) -> {
			tempParamValues.put(n, c.getText());
		});
		
		parameters.clear();
		for (var arg : sig.getArguments()) {
			panel.add(new GLabel("[" + arg.getName() + "]"));
			var field = new SymbolicFieldView(arg.getDataType().getLength()*8, "callstate_" + sig.getName()+"_"+arg.getName());
			panel.add(field);
			parameters.put(arg.getName(), field);
		}
		
		
		// attempt to restore the map built above
		tempParamValues.forEach((n,c) -> {
			if (parameters.containsKey(n)) {
				parameters.get(n).setText(c);
			}
		});
		
		panel.revalidate();
		panel.repaint();
	}
	
	public void setAddress(Address newAddr) {
		this.addressField.setText("0x" + newAddr.getOffsetAsBigInteger().toString(16));
	}
	
	@Override
	public JComponent getComponent() {
		return panel;
	}
	
	@Override
	public EntryPoint getConfig(Program p) {
		BigInteger addrInt = addressField.getValue();
		var factory = p.getAddressFactory();
		
		if (addrInt != null) {
			var addr = factory.getAddress(addrInt.toString(16));
			var ep = new EntryPoint.CallState(addr);
			ep.signature = signatureField.getText();

			BigInteger stackBaseInt = stackBaseField.getValue();
			if (stackBaseInt != null) {
				var stackBaseAddr = factory.getAddress(stackBaseInt.toString(16));
				ep.stackBase = stackBaseAddr;
			}
			
			parameters.forEach((k, v) -> {
				ep.params.add(new SymbolicField(v.getText(), v.getFieldWidth(), v.getFieldName(), k));
			});
			
			return ep;
		}
		
		return null;
	}
	
	@Override
	public void reset() {
		addressField.setText("");
		stackBaseField.setText("0x0500");
		
		Arrays.stream(panel.getComponents())
		.dropWhile(x -> x != signatureField)
		.skip(1)
		.forEach(x -> panel.remove(x));
	
		
		signatureField.setText("");
		
	}

	@Override
	public void updatePanel(EntryPoint e) {
		
		if (!(e instanceof EntryPoint.CallState)) {
			throw new IllegalArgumentException();
		}
		var entryPoint = (EntryPoint.CallState) e;
		
		addressField.setText("0x" + entryPoint.addr.getOffsetAsBigInteger().toString(16));
		stackBaseField.setText("0x" + entryPoint.stackBase.getOffsetAsBigInteger().toString(16));
		
		// Add this to the back of the event queue, because the handler that sets the signature field based on the address needs to resolve first.
		// updatePanel() will be run in the event handling thread, so using synchronisation primitives will just deadlock.
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				signatureField.setText(entryPoint.signature);
				for (var param : entryPoint.params) {
					parameters.put(param.originalName(), new SymbolicFieldView(param.width(), param.name(), param.code()));
				}
				refreshParamFields();

				
				panel.revalidate();
				panel.repaint();
			}
		});
		
	}

	@Override
	public String getDisplayName() {
		return "Call State";
	}
	
	@Override
	public void onProgramActivate(Program newProgram) {
		currentProgram = newProgram;
		
		var newProgramMaxAddress = newProgram.getAddressFactory().getDefaultAddressSpace().getMaxAddress().getOffsetAsBigInteger();
		
		addressField.setMaxValue(newProgramMaxAddress); 
		stackBaseField.setMaxValue(newProgramMaxAddress); 

		refreshParamFields();
	}
	
	@Override
	public void onReady(PluginTool tool) {
		this.codeViewerService = tool.getService(CodeViewerService.class);
	}

	@Override
	public Class<?> getSupportedClass() {
		return EntryPoint.CallState.class;
	}
	
	@Override
	public String getToolTipText() {
		return "Start at a state that's just about to call a function, with symbolic arguments";
	}

}
