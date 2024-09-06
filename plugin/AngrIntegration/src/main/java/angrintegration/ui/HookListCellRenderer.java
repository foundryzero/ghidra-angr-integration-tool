package angrintegration.ui;

import java.awt.Component;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JList;

import angrintegration.symbolic.Hook;
import angrintegration.symbolic.Hook.InlineHook;
import angrintegration.symbolic.Hook.SimProcedureHook;
import generic.theme.GIcon;

public class HookListCellRenderer extends DefaultListCellRenderer {

	@Override
	public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected,
			boolean cellHasFocus) {
		if (!(value instanceof Hook)) {
			throw new IllegalArgumentException("Only Hooks may be displayed in this list! Found " + value.getClass().toString());
		}
		var hook = (Hook) value;
		
		if (hook.enabled) { 
			setText(hook.toString());
		} else {
			setText("<html><strike>" + hook.toString() + "</strike></html>");
		}
		if (hook instanceof InlineHook) {
			setIcon(new GIcon("icon.debugger.step.into"));		
		} else if (hook instanceof SimProcedureHook) {
			setIcon(new GIcon("icon.debugger.step.over"));		
		}
		
		if (isSelected) {
			setBackground(list.getSelectionBackground());
			setForeground(list.getSelectionForeground());
		} else {
			setBackground(list.getBackground());
			setForeground(list.getForeground());
		}
		
		setEnabled(hook.enabled);

		
		return this;
	}
}
