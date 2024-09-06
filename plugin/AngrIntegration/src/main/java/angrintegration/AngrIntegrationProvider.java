package angrintegration;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.DefaultListModel;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.JToggleButton;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

import com.google.common.io.Files;
import com.google.gson.JsonParseException;
import com.google.gson.stream.JsonReader;

import angrintegration.AngrConfiguration.MemoryAccessPolicy;
import angrintegration.entrypoint.BlankStateView;
import angrintegration.entrypoint.CallStateView;
import angrintegration.entrypoint.EntryPointView;
import angrintegration.entrypoint.EntryStateView;
import angrintegration.entrypoint.FullInitStateView;
import angrintegration.exploregoal.AddressGoalView;
import angrintegration.exploregoal.CustomGoalView;
import angrintegration.exploregoal.ExploreGoalView;
import angrintegration.exploregoal.TerminationGoalView;
import angrintegration.exploregoal.UnconstrainedGoalView;
import angrintegration.symbolic.ConstraintEntry;
import angrintegration.symbolic.Hook;
import angrintegration.symbolic.VariableEntry;
import angrintegration.ui.EditableTable;
import angrintegration.ui.EditableTableModel;
import angrintegration.ui.ForceNoHorizontalScrollPanel;
import angrintegration.ui.HookListCellRenderer;
import angrintegration.ui.HookView;
import angrintegration.ui.ListTableModel;
import angrintegration.ui.VariablesTable;
import angrintegration.ui.VariablesTableModel;
import angrintegration.ui.WrapLayout;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import docking.widgets.button.GButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.label.GLabel;
import docking.widgets.list.GList;
import generic.jar.ResourceFile;
import generic.theme.GColor;
import generic.theme.GIcon;
import ghidra.app.context.ListingActionContext;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.layout.HorizontalLayout;
import ghidra.util.layout.VariableHeightPairLayout;

/**
 * Provides a JComponent containing the main UI for the AngrIntegrationPlugin.
 */
class AngrIntegrationProvider extends ComponentProvider {

	// Core UI panels //

	private JPanel mainUI;
	
	private JPanel buttonRowPanel;

	private JTabbedPane mainTabbedPane;

	private JPanel variablesPanel;

	private JPanel constraintsPanel;

	private JPanel runPanel;

	// Buttons panel //
	
	private GButton runButton;
	private GButton breakButton;
	
	private JPanel runButtonBox;
	
	private JTextPane statusDisplay;
	
	// Setup panel //

	private JPanel innerRunPanel;


	private JTextField binaryPathField;
	private JToggleButton binaryPathSyncButton;
	private GButton binaryPathOpenButton;
	private GhidraFileChooser fileChooser;

	private GComboBox<ArchitectureSpecEntry> architectureSpecBox;

	private GCheckBox loadExternalLibrariesCheckBox;
	
	private ButtonGroup entryPointButtonsGroup;
	private Map<Class<? extends EntryPointView>, JToggleButton> entryPointButtons;

	private EntryPointView currentEntryPoint;

	private ButtonGroup exploreConditionButtonsGroup;
	private Map<Class<? extends ExploreGoalView>, JToggleButton> exploreConditionButtons;

	private ExploreGoalView currentExploreCondition;

	private EditableTableModel<String> avoidModel;
	private EditableTable avoidTable;

	private GComboBox<MemoryAccessPolicy> memoryPolicyBox;
	private GComboBox<MemoryAccessPolicy> registerPolicyBox;
	
	private GCheckBox dropIntoConsoleCheckbox;
	private GCheckBox showDetailsCheckbox;
	
	private JTextArea codeWhenDoneArea;

	// Variables panel //

	private VariablesTableModel variablesModel;
	private EditableTable variablesTable;

	// Constraints & Hooks panel //

	private EditableTableModel<String> constraintsModel;
	private EditableTable constraintsTable;

	private DefaultListModel<Hook> hooksModel;
	private GList<Hook> hooksList;

	private HookView hookDetailsPanel;

	// Actions //

	private GhidraFileChooser configFileChooser;

	private AngrIntegrationPlugin p;


	private EntryPointView[] entryPointTypes = new EntryPointView[] { 
			new EntryStateView(), 
			new FullInitStateView(),
			new BlankStateView(),
			new CallStateView(null) // at construction time a program won't be loaded so can't be provided
	};

	private ExploreGoalView[] exploreConditionTypes = new ExploreGoalView[] { new TerminationGoalView(),
			new AddressGoalView(), new UnconstrainedGoalView(), new CustomGoalView() };

	public AngrIntegrationProvider(AngrIntegrationPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.p = plugin;

		this.entryPointButtons = new LinkedHashMap<Class<? extends EntryPointView>, JToggleButton>();

		this.exploreConditionButtons = new LinkedHashMap<Class<? extends ExploreGoalView>, JToggleButton>();

		buildPanel();
		createActions();
	}

	// Customize GUI
	private void buildPanel() {
		
		mainUI = new JPanel(new BorderLayout());
		
		mainTabbedPane = new JTabbedPane();

		variablesPanel = new JPanel(new BorderLayout());
		constraintsPanel = new JPanel(new BorderLayout());
		runPanel = new JPanel(new BorderLayout());

		mainTabbedPane.add(runPanel, "Setup");
		mainTabbedPane.add(variablesPanel, "Variables");
		mainTabbedPane.add(constraintsPanel, "Constraints & Hooks");

		buildRunTab();
		buildVariablesTab();
		buildConstraintsTab();
		
		buildButtonsPanel();
		
		mainUI.add(mainTabbedPane, BorderLayout.CENTER);
		mainUI.add(buttonRowPanel, BorderLayout.PAGE_END);
		
		setVisible(true); // make a frame and show the UI if it's not already being shown
	}
	
	private void buildButtonsPanel() {
		buttonRowPanel = new JPanel(new BorderLayout());

		statusDisplay = new JTextPane();
		statusDisplay.setEnabled(false);
		
		// all this just to right align the pane
		StyledDocument style = statusDisplay.getStyledDocument();
		SimpleAttributeSet rightAlign= new SimpleAttributeSet();
		StyleConstants.setAlignment(rightAlign, StyleConstants.ALIGN_RIGHT);
		style.setParagraphAttributes(0, style.getLength(), rightAlign, false);		
		
		buttonRowPanel.add(statusDisplay, BorderLayout.CENTER);

		runButtonBox = new JPanel(new BorderLayout());
		
		runButton = new GButton("Start");
		runButton.setPreferredSize(new Dimension(150, 50));
		
		breakButton = new GButton("Break");
		breakButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				p.angrIf.doBreak();
			}
		});
		
		runButtonBox.add(runButton, BorderLayout.CENTER);
		// runButtonBox.add(breakButton, BorderLayout.PAGE_END);
		
		buttonRowPanel.add(runButtonBox, BorderLayout.LINE_END);

		/*
		 * This is the main entry point into angr code, where a AngrConfiguration is
		 * constructed from the state of the UI, and angr is started.
		 */
		runButton.addActionListener(new RunButtonListener());

	}

	/**
	 * Constructs the entirity of the 'RUN' tab of the main UI.
	 */
	private void buildRunTab() {
		// VariableHeightPairLayout puts components in a nx2 grid, with components added
		// left to right, top to bottom.
		// ForceNoHorizontalScrollPanel implements Scrollable but only in one direction,
		// forcing it to fit into it's box when resized.
		innerRunPanel = new ForceNoHorizontalScrollPanel(new VariableHeightPairLayout(5, 5));

		runPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

		// Build the various parts of the tab
		this.buildBinaryPathBox();
		this.buildArchitectureBox();
		this.buildOptionsCheckBoxes();
		this.buildEntryPointSelection();
		this.buildExploreConidtionSelection();
		this.buildAvoidAddressesBox();
		this.buildMiscOptions();

		

		var runScrollPane = new JScrollPane(innerRunPanel, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		runScrollPane.setBorder(javax.swing.BorderFactory.createEmptyBorder());
		runScrollPane.getViewport().setBackground(new GColor("laf.color.Panel.background"));
		runPanel.add(runScrollPane, BorderLayout.CENTER);
	}

	private void buildBinaryPathBox() {
		var binaryPathLabel = new GLabel("Binary path:");
		var binaryPathPanel = new JPanel(new BorderLayout());
		
		var buttonsPanel = new JPanel(new HorizontalLayout(5));

		binaryPathField = new JTextField();
		binaryPathPanel.add(binaryPathField, BorderLayout.CENTER);

		binaryPathField.setToolTipText("The path to the binary being analyzed");
		
		binaryPathSyncButton = new JToggleButton(new GIcon("icon.debugger.connect"));
		binaryPathSyncButton.setToolTipText(
				"Sync the binary path with the currently selected Ghidra program (may not be accurate for remote projects)");
		binaryPathOpenButton = new GButton(new GIcon("icon.folder.open"));
		binaryPathOpenButton.setToolTipText("Choose binary path file...");

		buttonsPanel.add(binaryPathOpenButton);
		buttonsPanel.add(binaryPathSyncButton);

		binaryPathPanel.add(buttonsPanel, BorderLayout.LINE_END);

		innerRunPanel.add(binaryPathLabel);
		innerRunPanel.add(binaryPathPanel);

		// Disable the two ways of setting the field, since sync is on by default
		binaryPathField.setEnabled(false);
		binaryPathOpenButton.setEnabled(false);

		fileChooser = new GhidraFileChooser(binaryPathOpenButton);

		// Open a (modal) file picker to select the binary path
		binaryPathOpenButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				var file = fileChooser.getSelectedFile(true);
				if (file != null) {
					binaryPathField.setText(file.getAbsolutePath());
				}
			}
		});

		// Toggles sync mode, where the binary path will be kept in sync with the current Ghidra program
		// see onProgramChanged at the bottom of this file
		binaryPathSyncButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (binaryPathSyncButton.isSelected()) {
					binaryPathField.setEnabled(false);
					binaryPathOpenButton.setEnabled(false);
					if (p.getCurrentProgram() != null) {
						binaryPathField.setText(new File(p.getCurrentProgram().getExecutablePath()).getAbsolutePath());
					}
				} else {
					binaryPathField.setEnabled(true);
					binaryPathOpenButton.setEnabled(true);
				}
			}
		});

		// Enable sync mode by default
		binaryPathSyncButton.doClick();
	}

	/**
	 * Record representing a single entry in the list of architectures. This is used
	 * rather than just the shortName to avoid having to search for architectures
	 * multiple times.
	 */
	private static record ArchitectureSpecEntry(String shortName, String path) {
		@Override
		public String toString() {
			return shortName;
		}
	}

	private void buildArchitectureBox() {
		var architectureSpecLabel = new GLabel("Architecture:");
		architectureSpecBox = new GComboBox<ArchitectureSpecEntry>();
		architectureSpecBox.setToolTipText("The Architecture Interface to use (taken from data/architectures)");

		this.refreshArchitectureBox();

		innerRunPanel.add(architectureSpecLabel);
		innerRunPanel.add(architectureSpecBox);
	}

	/**
	 * Regenerate the list of architectures from disk. Architectures must provide a
	 * class that implements ArchitectureInterface; this is not (and can't really
	 * easily be) checked here.
	 */
	private void refreshArchitectureBox() {
		this.architectureSpecBox.removeAllItems(); // This will reset the box to it's default element, which should be
													// fine?

		// Look for everything in the architectures folder, with the special case for
		// the base class
		try {
			var archDirectory = Application.getModuleDataSubDirectory("architectures");
			for (ResourceFile f : archDirectory.listFiles()) {
				if (!f.isDirectory()) {
					if (f.getName().equals("architecture_interface.py")) { // special case: the interface itself
																			// provides a set of defaults
						this.architectureSpecBox
								.addItem(new ArchitectureSpecEntry("Default", f.getFile(true).getAbsolutePath()));
						continue;
					}
					var index = f.getName().lastIndexOf('.');
					this.architectureSpecBox.addItem(new ArchitectureSpecEntry(f.getName().substring(0, index),
							f.getFile(true).getAbsolutePath()));
				}
			}
		} catch (IOException e) {
			Msg.showError(this, null, "Failed to get architectures!", "Failed to get architectures!");
		}
	}
	
	/**
	 * Sets the current architecture. If it isn't already in the list, will do nothing.
	 * @param path the location of the new architecture to set to.
	 */
	public void setArchitecture(String path) {
		var model = architectureSpecBox.getModel();
		var size = model.getSize();
		for (int i=0; i<size; i++) {
			if (model.getElementAt(i).path().equals(path)) {
				architectureSpecBox.setSelectedIndex(i);
			}
		}
	}
	
	private void buildOptionsCheckBoxes() {
		loadExternalLibrariesCheckBox = new GCheckBox("Load external libraries");
		loadExternalLibrariesCheckBox.setToolTipText("Should external libraries be attempted to be loaded by angr? NOTE: This will not nessecarily load the same versions of libraries that are in your Ghidra project, and could have strange consequences.");
		
		innerRunPanel.add(new GLabel("")); // padding
		innerRunPanel.add(loadExternalLibrariesCheckBox);
	}

	private void buildEntryPointSelection() {
		entryPointButtonsGroup = new ButtonGroup(); // handles the radio button semantics

		// Hook up the call state to the pluginTool (used for the set location button to
		// work)

		// NOTE: WrapLayout is like FlowLayout but actually sets it's preferred height
		// properly
		// WrapLayout is MIT licenced by Rob Camick
		var buttonsPanel = new JPanel(new WrapLayout(FlowLayout.LEFT));

		var paddingLabel = new GLabel(""); // Empty component

		for (var ep : entryPointTypes) {

			JToggleButton btn = new JToggleButton(ep.getDisplayName());
			btn.setToolTipText(ep.getToolTipText());
			btn.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					// get the index of the button array
					var buttonListIndex = Arrays.asList(innerRunPanel.getComponents()).indexOf(buttonsPanel);

					// the newly selected EntryPoint might have no associated component, so remove
					// the padding and re-add it later if needed
					innerRunPanel.remove(paddingLabel);

					for (var other : entryPointTypes) {
						if (other.getComponent() != null) {
							innerRunPanel.remove(other.getComponent());
						}
					}

					if (ep.getComponent() != null) { // if this EntryPoint as an additional options UI to display
						innerRunPanel.add(paddingLabel, null, buttonListIndex + 1); // add it directly after the entry
																					// point buttons i.e. just below it
						innerRunPanel.add(ep.getComponent(), null, buttonListIndex + 2);
					}

					currentEntryPoint = ep;

					// layout may have changed, force a revalidation
					p.refreshListing();	
					runPanel.validate();
					runPanel.repaint();
				}
			});
			this.entryPointButtons.put(ep.getClass(), btn);
			buttonsPanel.add(btn);
			entryPointButtonsGroup.add(btn);
		}

		// Simulate a click for the default button
		if (entryPointButtons.get(EntryStateView.class) != null) {
			entryPointButtons.get(EntryStateView.class).doClick();
		}

		innerRunPanel.add(new GLabel("Entry Point:"));
		innerRunPanel.add(buttonsPanel);
	}

	private void buildExploreConidtionSelection() {
		exploreConditionButtonsGroup = new ButtonGroup(); // handles the radio button semantics

		// NOTE: WrapLayout is like FlowLayout but actually sets it's preferred height
		// properly
		// WrapLayout is MIT licenced by Rob Camick
		var buttonsPanel = new JPanel(new WrapLayout(FlowLayout.LEFT));

		var paddingLabel = new GLabel("");

		for (var ec : exploreConditionTypes) {
			JToggleButton btn = new JToggleButton(ec.getDisplayName());
			btn.setToolTipText(ec.getToolTipText());

			btn.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {

					// get the index of the button array
					var buttonListIndex = Arrays.asList(innerRunPanel.getComponents()).indexOf(buttonsPanel);

					innerRunPanel.remove(paddingLabel);
					for (var other : exploreConditionTypes) {
						if (other.getComponent() != null) {
							innerRunPanel.remove(other.getComponent());
						}
					}
					if (ec.getComponent() != null) {
						innerRunPanel.add(paddingLabel, null, buttonListIndex + 1);
						innerRunPanel.add(ec.getComponent(), null, buttonListIndex + 2);
					}

					currentExploreCondition = ec;

					// layout may have changed, force a revalidation
					p.refreshListing();	
					runPanel.validate();
					runPanel.repaint();
				}
			});
			this.exploreConditionButtons.put(ec.getClass(), btn);
			buttonsPanel.add(btn);
			exploreConditionButtonsGroup.add(btn);
		}

		// Simulate a click for the default button
		if (exploreConditionButtons.get(TerminationGoalView.class) != null) {
			exploreConditionButtons.get(TerminationGoalView.class).doClick();
		}

		innerRunPanel.add(new GLabel("Exploration Goal:"));
		innerRunPanel.add(buttonsPanel);
	}

	private void buildAvoidAddressesBox() {
		avoidModel = new ListTableModel<String>("0x0", "Avoid");
		avoidTable = new EditableTable(avoidModel);
		
		// Changing the table could change the currently active listing hints, so refresh those
		avoidModel.addTableModelListener(new TableModelListener() {
			@Override
			public void tableChanged(TableModelEvent e) {
				p.refreshListing();			
			}
		});

		innerRunPanel.add(new GLabel("Avoid addresses:"));
		innerRunPanel.add(avoidTable.getComponent());
	}

	private void buildMiscOptions() {
		innerRunPanel.add(new GLabel("Uninitialized memory:"));
		memoryPolicyBox = new GComboBox<MemoryAccessPolicy>(MemoryAccessPolicy.values());
		innerRunPanel.add(memoryPolicyBox);
		
		innerRunPanel.add(new GLabel("Uninitialized registers:"));
		registerPolicyBox = new GComboBox<MemoryAccessPolicy>(MemoryAccessPolicy.values());
		innerRunPanel.add(registerPolicyBox);
		
		innerRunPanel.add(new GLabel("")); // padding
		dropIntoConsoleCheckbox = new GCheckBox("Drop into REPL when done");
		innerRunPanel.add(dropIntoConsoleCheckbox);
		
		innerRunPanel.add(new GLabel("")); // padding
		showDetailsCheckbox = new GCheckBox("Automatically show a solution for all variables when done");
		innerRunPanel.add(showDetailsCheckbox);
		
		innerRunPanel.add(new GLabel("Completion hook:"));
		codeWhenDoneArea = new JTextArea();
		var codeWhenDonePane = new JScrollPane(codeWhenDoneArea);
		codeWhenDonePane.setPreferredSize(new Dimension(0, 150));
		innerRunPanel.add(codeWhenDonePane);
	}

	private void buildVariablesTab() {
		variablesModel = new VariablesTableModel();
		variablesTable = new VariablesTable(null, variablesModel);

		variablesPanel.add(variablesTable.getComponent(), BorderLayout.CENTER);
	}

	private void buildConstraintsTab() {
		var constraintsTablePanel = buildConstraintsTablePanel();
		var hooksPanel = buildHooksPanel();

		constraintsPanel.add(new JSplitPane(JSplitPane.VERTICAL_SPLIT, constraintsTablePanel, hooksPanel));
	}

	private JPanel buildHooksPanel() {
		var hooksPanel = new JPanel(new BorderLayout(5, 5));
		hooksPanel.setBorder(new EmptyBorder(5, 5, 5, 5));

		var hooksListPanel = new JPanel(new BorderLayout(5, 5));
		hooksPanel.add(hooksListPanel, BorderLayout.LINE_START);

		hooksModel = new DefaultListModel<Hook>();
		hooksList = new GList<Hook>(hooksModel);
		hooksList.setCellRenderer(new HookListCellRenderer());

		var pane = new JScrollPane(hooksList);
		pane.setPreferredSize(new Dimension(200, 0));
		hooksListPanel.add(pane, BorderLayout.CENTER);

		var hooksListHeader = new Box(BoxLayout.LINE_AXIS);
		hooksListHeader.add(new GLabel("Hooks"));

		var addInlineHookButton = new GButton(new GIcon("icon.debugger.step.into"));
		var addSimProcHookButton = new GButton(new GIcon("icon.debugger.step.over"));
		var removeHookButton = new GButton(new GIcon("icon.delete"));

		hooksListHeader.add(Box.createHorizontalGlue());
		hooksListHeader.add(addInlineHookButton);
		hooksListHeader.add(Box.createHorizontalStrut(5));
		hooksListHeader.add(addSimProcHookButton);
		hooksListHeader.add(Box.createHorizontalStrut(5));
		hooksListHeader.add(removeHookButton);

		addInlineHookButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				hooksModel.addElement(new Hook.InlineHook(p.getProgramLocation().getAddress()));
				hooksList.setSelectedIndex(hooksModel.size() - 1);
			}
		});
		addSimProcHookButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				hooksModel.addElement(new Hook.SimProcedureHook(p.getProgramLocation().getAddress()));
				hooksList.setSelectedIndex(hooksModel.size() - 1);
			}
		});
		removeHookButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (hooksList.getSelectedIndex() != -1) {
					hooksModel.remove(hooksList.getSelectedIndex());
				}
			}
		});

		hooksListPanel.add(hooksListHeader, BorderLayout.PAGE_START);

		hookDetailsPanel = new HookView(p.getTool(), () -> {
			p.refreshListing();
			hooksList.revalidate();
			hooksList.repaint();
		}); // pass in a lambda to be called to repaint any external UI that depends on the hook

		hooksList.addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				hookDetailsPanel.setHook(hooksList.getSelectedValue());
			}
		});
		
		hooksList.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					var index = hooksList.locationToIndex(e.getPoint());
					var hook = hooksList.getModel().getElementAt(index);
					hook.enabled = !hook.enabled;
					hooksList.revalidate();
					hooksList.repaint();
					hookDetailsPanel.refresh();
				}
			}
		});

		hooksPanel.add(hookDetailsPanel, BorderLayout.CENTER);

		return hooksPanel;
	}

	private JPanel buildConstraintsTablePanel() {
		var constraintsTablePanel = new JPanel(new BorderLayout(5, 5));
		constraintsTablePanel.setBorder(new EmptyBorder(5, 5, 5, 5));

		constraintsModel = new ListTableModel<String>("", "Constraint");
		constraintsTable = new EditableTable("Global Constraints", constraintsModel);

		constraintsTablePanel.add(constraintsTable.getComponent(), BorderLayout.CENTER);
		return constraintsTablePanel;
	}

	/**
	 * Creates ghidra DockingActions for the provider.
	 */
	private void createActions() {
		registerLocalAction(new DockingAction("Refresh Architecture List", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				refreshArchitectureBox();
			}
		}, "icon.refresh");


		registerGlobalAction(new DockingAction("Start/Stop angr", getName()) {
			public void actionPerformed(ActionContext context) {
				runButton.doClick();
			}
		}, "icon.run");


		configFileChooser = new GhidraFileChooser(binaryPathOpenButton);
		
		registerLocalAction(new DockingAction("Save angr Configuration", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				var config = makeConfiguration();
				var config_json = config.toJson(p.getCurrentProgram()).getBytes();
				
				var file = configFileChooser.getSelectedFile(true);
				if (file == null) {
					return;
				}
				
				try {
					Files.write(config_json, file);
				} catch (IOException e) {
					Msg.showError(this, null, "Failed to write config file!", e);
				}
			}
		}, "icon.save");

		
		registerLocalAction(new DockingAction("Load angr Configuration", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				var file = configFileChooser.getSelectedFile(true);
				if (file == null || !file.exists()) {
					return;
				}
				
				try {
					JsonReader reader = new JsonReader(new FileReader(file));
					AngrConfiguration config = AngrConfiguration.from(reader, p.getCurrentProgram());
					loadConfiguration(config);
				} catch (FileNotFoundException e) {
					// should be unreachable because this was checked already!
				} catch (JsonParseException e) {
					Msg.showError(this, null, "Failed to load file!", e);
					return;
				}
				
			}
		}, "icon.folder.open");
		
		registerLocalAction(new DockingAction("Reset", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (OptionDialog.showOptionDialog(mainUI, "Are you sure?", "Are you sure you wish to reset the plugin?", "Reset") == 1) {
					reset();
				}
			}
		}, "icon.content.handler.program");
		
		registerRightClickAction(new DockingAction("Add as avoid", getName()) {
			
			@Override
			public boolean isAddToPopup(ActionContext context) {
				// This context menu only makes sense inside a Listing window.
				return context instanceof ListingActionContext;
			}
			
			@Override
			public void actionPerformed(ActionContext context) {
				if (!(context instanceof ListingActionContext)) {
					return;
				}
				
				ListingActionContext lContext = (ListingActionContext) context;
				ProgramSelection selection = lContext.getSelection();
				
				for (var addrRange : selection) {
					for (var addr: addrRange) {
						avoidModel.addRow("0x" + addr.getOffsetAsBigInteger().toString(16));
					}
				}
				
				mainTabbedPane.setSelectedComponent(runPanel);
				
				if (selection.isEmpty()) {
					// if there's no selection, use the current cursor position instead
					ProgramLocation location = lContext.getLocation();
					avoidModel.addRow("0x" + location.getAddress().getOffsetAsBigInteger().toString(16));
				}
				
			}
		}, "icon.not.allowed");
		
		registerRightClickAction(new DockingAction("Add as target", getName()) {

			@Override
			public boolean isAddToPopup(ActionContext context) {
				// This context menu only makes sense inside a Listing window.
				return context instanceof ListingActionContext;
			}
			
			@Override
			public void actionPerformed(ActionContext context) {
				if (!(context instanceof ListingActionContext)) {
					return;
				}
				
				ListingActionContext lContext = (ListingActionContext) context;
				ProgramSelection selection = lContext.getSelection();
				
				AddressGoalView addrView = null;
				
				exploreConditionButtons.get(AddressGoalView.class).doClick();
				for (var ec : exploreConditionTypes) {
					if (ec instanceof AddressGoalView) {
						addrView = ((AddressGoalView) ec);
					}
				}
				
				mainTabbedPane.setSelectedComponent(runPanel);
				
				if (addrView == null) {
					Msg.showError(this, null, "Could not obtain AddressGoalView!", "AddressGoalView was null. This is a bug!");
					return;
				}

				for (var addrRange : selection) {
					for (var addr: addrRange) {
						addrView.addAddress(addr);
					}
				}
				
				if (selection.isEmpty()) {
					// if there's no selection, use the current cursor position instead
					ProgramLocation location = lContext.getLocation();
					addrView.addAddress(location.getAddress());
				}
				
			}
		}, "icon.plugin.checksum.select");
		
		registerRightClickAction(new DockingAction("Set call state address", getName()) {
			@Override
			public boolean isAddToPopup(ActionContext context) {
				// This context menu only makes sense inside a Listing window.
				return context instanceof ListingActionContext;
			}
			
			@Override
			public void actionPerformed(ActionContext context) {
				if (!(context instanceof ListingActionContext)) {
					return;
				}
				
				ListingActionContext lContext = (ListingActionContext) context;
				ProgramLocation loc = lContext.getLocation();
				mainTabbedPane.setSelectedComponent(runPanel);
				entryPointButtons.get(CallStateView.class).doClick();
				for (var ep : entryPointTypes) {
					if (ep instanceof CallStateView) {
						((CallStateView) ep).setAddress(loc.getAddress());
					}
				}
				 
			}
		}, "icon.navigate.in");
		
		registerRightClickAction(new DockingAction("Set blank state address", getName()) {
			@Override
			public boolean isAddToPopup(ActionContext context) {
				// This context menu only makes sense inside a Listing window.
				return context instanceof ListingActionContext;
			}
			
			@Override
			public void actionPerformed(ActionContext context) {
				if (!(context instanceof ListingActionContext)) {
					return;
				}
				
				ListingActionContext lContext = (ListingActionContext) context;
				ProgramLocation loc = lContext.getLocation();
				
				mainTabbedPane.setSelectedComponent(runPanel);
				entryPointButtons.get(BlankStateView.class).doClick();
				for (var ep : entryPointTypes) {
					if (ep instanceof BlankStateView) {
						((BlankStateView) ep).setAddress(loc.getAddress());
					}
				}
				 
			}
		}, "icon.navigate.in");
		
		registerRightClickAction(new DockingAction("Create inline hook here", getName()) {
			@Override
			public boolean isAddToPopup(ActionContext context) {
				// This context menu only makes sense inside a Listing window.
				return context instanceof ListingActionContext;
			}
			
			@Override
			public void actionPerformed(ActionContext context) {
				if (!(context instanceof ListingActionContext)) {
					return;
				}
				
				ListingActionContext lContext = (ListingActionContext) context;
				ProgramLocation loc = lContext.getLocation();
				
				mainTabbedPane.setSelectedComponent(constraintsPanel);
				hooksModel.addElement(new Hook.InlineHook(loc.getAddress()));
				hooksList.setSelectedIndex(hooksModel.size() - 1);
								 
			}
		}, "icon.debugger.step.into");		
		registerRightClickAction(new DockingAction("Create SimProcedure hook here", getName()) {
			@Override
			public boolean isAddToPopup(ActionContext context) {
				// This context menu only makes sense inside a Listing window.
				return context instanceof ListingActionContext;
			}
			
			@Override
			public void actionPerformed(ActionContext context) {
				if (!(context instanceof ListingActionContext)) {
					return;
				}
				
				ListingActionContext lContext = (ListingActionContext) context;
				ProgramLocation loc = lContext.getLocation();
				
				mainTabbedPane.setSelectedComponent(constraintsPanel);
				hooksModel.addElement(new Hook.SimProcedureHook(loc.getAddress()));
				hooksList.setSelectedIndex(hooksModel.size() - 1);
								 
			}
		}, "icon.debugger.step.over");		
	}
	
	private void registerGlobalAction(DockingAction action, String iconKey) {
		action.setToolBarData(new ToolBarData(new GIcon(iconKey)));
		registerAction(action, false);
	}
	
	private void registerLocalAction(DockingAction action, String iconKey) {
		action.setToolBarData(new ToolBarData(new GIcon(iconKey)));
		registerAction(action, true);
	}
	
	private void registerRightClickAction(DockingAction action, String iconKey) {
		action.setPopupMenuData(new MenuData(new String[] {"angr", action.getName()}, new GIcon(iconKey)));
		registerAction(action, false);
	}
	
	/**
	 * Registers an action, as either local or global, with no help location.
	 * 
	 * To find ghidra icon strings to use, see Edit -> Theme -> Configure -> Icons on the main (project) window
	 * of Ghidra.
	 * 
	 * @param action the action to add
	 * @param isLocal true if the action should be added to the provider rather than the main toolbar
	 */
	private void registerAction(DockingAction action, boolean isLocal) {
		action.setEnabled(true);
		action.markHelpUnnecessary();
		if (isLocal) {
			dockingTool.addLocalAction(this, action);
		} else {
			dockingTool.addAction(action);
		}
	}

	/**
	 * Called by the Ghidra plugin system to display the component.
	 * 
	 * @return the root JComponnent of the plugin UI
	 */
	@Override
	public JComponent getComponent() {
		return mainUI;
	}

	/**
	 * Callback when angr finishes execution, one way or another.
	 */
	public void angrFinished() {
		p.statusReport(""); // clear the status report field
		this.runButton.setText("Start");
		runButtonBox.remove(breakButton);
	}

	/**
	 * Callback when the currently active program changes.
	 * 
	 * @param newProgram the newly activated program
	 */
	public void onProgramActivated(Program newProgram) {
		if (binaryPathSyncButton != null) {
			if (binaryPathSyncButton.isSelected()) {
				binaryPathField.setText(new File(newProgram.getExecutablePath()).getAbsolutePath());
				
				if(p.angrIf != null) {
				p.angrIf.setSensibleArchitecture(newProgram);
				}
			}
		}

		for (var ep : entryPointTypes) {
			ep.onProgramActivate(newProgram);
		}

		for (var ex : exploreConditionTypes) {
			ex.onProgramActivate(newProgram);
		}

		hookDetailsPanel.onProgramActivate(newProgram);

	}

	/**
	 * Perform initialization on the UI state that needs access to services from the
	 * PluginTool.
	 * 
	 * @param tool the PluginTool to aquire services from
	 */
	public void onReady(PluginTool tool) {
		for (var ep : entryPointTypes) {
			ep.onReady(tool);
		}
		for (var ex : exploreConditionTypes) {
			ex.onReady(tool);
		}
	}

	/**
	 * Handle a new status report from the angr process
	 * 
	 * @param report The new report string to show
	 */
	public void onStatusReport(String report) {
		// make newlines real - they're passed escaped, because if they're 'real' newlines then the status report will
		// get broken up into multiple lines which won't work.
		statusDisplay.setText(report.replace("\\n", "\n"));
	}
	
	/**
	 * Event fired when the REPL starts up.
	 */
	public void onREPLStart() {
		
		// no point breaking if the repl is already open
		runButtonBox.remove(breakButton);
	} 
	
	/**
	 * Event fired when a REPL session ends.
	 */
	public void onREPLEnd() {
		runButtonBox.add(breakButton, BorderLayout.PAGE_END);
	}
	
	
	/**
	 * Collects the state of the Provider into a AngrConfiguration, to be saved or passed to angr.
	 * 
	 * @return the created AngrConfiguration
	 */
	protected AngrConfiguration makeConfiguration() {
		var config = new AngrConfiguration();

		config.binaryPath = binaryPathField.getText();

		// architectureSpecBox contians only ArchitectureSpecEntrys so this cast is safe
		config.architectureName = ((ArchitectureSpecEntry) architectureSpecBox.getSelectedItem()).path;

		try {
			// relative to the plugin's data/ folder
			var archDirectory = Application.getModuleDataSubDirectory("architectures");
			config.architectureSpecPath = archDirectory.getAbsolutePath();
		} catch (IOException ex) {
			// oh no!
			Msg.showError(this, null, "Failed to find architecture file!", ex);
			return null;
		}
		
		config.loadExternalLibraries = loadExternalLibrariesCheckBox.isSelected();

		config.entryPoint = currentEntryPoint.getConfig(p.getCurrentProgram());
		config.exploreCondition = currentExploreCondition.getConfig(p.getCurrentProgram());

		var factory = p.getCurrentProgram().getAddressFactory();
		var avoidAddrs = new ArrayList<Address>();

		for (var addrStr : avoidTable.getModel().getRows()) {
			// safe cast: the model will always store strings
			avoidAddrs.add(factory.getAddress((String) addrStr));
		}
		config.avoidAddrs = avoidAddrs;
		
		config.memoryAccessPolicy = (MemoryAccessPolicy) memoryPolicyBox.getSelectedItem();
		config.registerAccessPolicy = (MemoryAccessPolicy) registerPolicyBox.getSelectedItem();

		config.repl = dropIntoConsoleCheckbox.isSelected();
		config.showDetails = showDetailsCheckbox.isSelected();
		
		config.codeWhenDone = codeWhenDoneArea.getText();

		// Variables Panel //

		config.symbolicVariables = new ArrayList<VariableEntry>();

		for (var variable : variablesModel.getRows()) {
			config.symbolicVariables.add(variable);
		}

		// Constraints //

		config.constraints = new ArrayList<ConstraintEntry>();

		for (var constraintString : constraintsModel.getRows()) {
			var constraint = new ConstraintEntry(constraintString);
			config.constraints.add(constraint);
		}

		// Hooks //

		/* Copy the hooks data into an list before sending it
		   This is so other code can feel free to mutate (e.g. clear) config.hooks without affecting the UI
		   in strange and dangerous ways */
		config.hooks = Arrays
				.asList(Arrays.copyOf(hooksModel.toArray(), hooksModel.toArray().length, Hook[].class));
		
		return config;
	}
	
	private void loadConfiguration(AngrConfiguration config) {		
		binaryPathField.setText(config.binaryPath);
		
		for (int i = 0; i < architectureSpecBox.getItemCount(); i++) {
			if (config.architectureName.equals(architectureSpecBox.getItemAt(i).path)) {
				architectureSpecBox.setSelectedIndex(i);
			}
		}
		
		loadExternalLibrariesCheckBox.setSelected(config.loadExternalLibraries);
		
		for (var entryPointView : entryPointTypes) {
			if (entryPointView.getSupportedClass().equals(config.entryPoint.getClass())) {
				entryPointView.updatePanel(config.entryPoint);
				entryPointButtons.get(entryPointView.getClass()).doClick();
			}
		}
		
		for (var exploreConditionView : exploreConditionTypes) {
			if (exploreConditionView.getSupportedClass().equals(config.exploreCondition.getClass())) {
				exploreConditionView.updatePanel(config.exploreCondition);
				exploreConditionButtons.get(exploreConditionView.getClass()).doClick();
			}
		}
		
		avoidModel.clear();
		for (var addr : config.avoidAddrs) {
			avoidModel.addRow("0x" + addr.getOffsetAsBigInteger().toString(16));
		}
		
		memoryPolicyBox.setSelectedItem(config.memoryAccessPolicy);
		registerPolicyBox.setSelectedItem(config.registerAccessPolicy);
		
		dropIntoConsoleCheckbox.setSelected(config.repl);
		showDetailsCheckbox.setSelected(config.showDetails);
		
		codeWhenDoneArea.setText(config.codeWhenDone);
		
		// Variables Panel //
		
		variablesModel.clear();
		for (var variable : config.symbolicVariables) {
			variablesModel.addRow(variable);
		}
		
		// Constraints //
		
		constraintsModel.clear();
		for (var constraint : config.constraints) {
			constraintsModel.addRow(constraint.code());
		}
		
		// Hooks //
		
		hooksModel.clear();
		hooksModel.addAll(config.hooks);
	}
	
	/**
	 * Resets the plugin to an initialized state
	 */
	private void reset() {
		architectureSpecBox.setSelectedIndex(0);
		loadExternalLibrariesCheckBox.setSelected(false);
		
		for (var entryPointView : entryPointTypes) {
			entryPointView.reset();
		}
		entryPointButtons.get(entryPointTypes[0].getClass()).doClick();
		
		for (var exploreConditionView : exploreConditionTypes) {
			exploreConditionView.reset();
		}
		exploreConditionButtons.get(exploreConditionTypes[0].getClass()).doClick();
		
		avoidModel.clear();
		memoryPolicyBox.setSelectedIndex(0);
		registerPolicyBox.setSelectedIndex(0);
		
		dropIntoConsoleCheckbox.setSelected(false);
		showDetailsCheckbox.setSelected(false);
		
		codeWhenDoneArea.setText("");
		
		variablesModel.clear();
		constraintsModel.clear();
		hooksModel.clear();
	}

	private class RunButtonListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
            if(p.angrIf == null) {
                Msg.showWarn(this, null, "Virtual environment not set!", "Please set up a virtual environment containing angr, and provide a path to it in the tool options.");
                return;
            }
			
			var codeViewer = p.getTool().getService(CodeViewerService.class);
			codeViewer.getListingPanel().updateDisplay(true);
			
			if (p.angrIsRunning == false) {

				var config = makeConfiguration();
				
				if (config == null) {
					return; // some error occured, cannot continue starting angr
				}

				p.startAngr(config); // GO!
				runButton.setText("Stop");
				runButtonBox.add(breakButton, BorderLayout.PAGE_END);
			} else {
				p.stopAngr();
				runButton.setText("Start");
				runButtonBox.remove(breakButton);
			}
		}
	}
}