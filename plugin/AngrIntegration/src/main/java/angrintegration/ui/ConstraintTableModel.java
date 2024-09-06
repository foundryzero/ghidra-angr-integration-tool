package angrintegration.ui;

import angrintegration.symbolic.ConstraintEntry;

/**
 * A model for tables of constraints. Currently just glues things such that the Table thinks it's a table of strings,
 * but could be useful in the future if ConstraintEntrys ever need more data.
 * 
 * (or in the future if java actually adds type aliasing and then ConstraintEntry can just be a name for String)
 */
public class ConstraintTableModel extends ListTableModel<ConstraintEntry> {
	public ConstraintTableModel(ConstraintEntry defaultT, String title) {
		super(defaultT, title);
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		return ((ConstraintEntry) super.getValueAt(rowIndex, columnIndex)).code();
	}
	
	@Override
	public void setValueAt(Object value, int row, int col) {
		super.setValueAt(new ConstraintEntry((String) value), row, col);
	}
	
}
