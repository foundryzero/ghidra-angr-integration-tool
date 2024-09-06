package angrintegration.ui;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.table.AbstractTableModel;

import angrintegration.symbolic.VariableEntry;

public class VariablesTableModel extends AbstractTableModel implements EditableTableModel<VariableEntry> {

	public static final String[] COL_NAMES = {"Target", "Name", "Length", "Value"};
	public static final int NAME_COL_INDEX = 1;
	public static final int LENGTH_COL_INDEX = 2;
	public static final int VALUE_COL_INDEX = 3;
	
	private List<VariableEntry> backer;
	
	public VariablesTableModel() {
		backer = new ArrayList<VariableEntry>();
	}

	@Override
	public int getRowCount() {
 		return backer.size();
	}

	@Override
	public int getColumnCount() {
		return 4;
	}

	@Override
	public String getColumnName(int columnIndex) {
		return COL_NAMES[columnIndex];
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == 2) {
			return Integer.class;
		}
		return String.class;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return true;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		return backer.get(rowIndex).getByIndex(columnIndex);
	}

	@Override
	public void setValueAt(Object aValue, int row, int col) {
		backer.set(row, backer.get(row).setByIndex(aValue, col));
		fireTableCellUpdated(row, col);
	}

	@Override
	public List<VariableEntry> getRows() {
		return backer;
	}

	@Override
	public void addRow() {
		this.addRow(new VariableEntry("", "", 8, ""));
	}

	@Override
	public void addRow(VariableEntry row) {
		backer.add(row);
		fireTableDataChanged();
	}

	@Override
	public void removeRow(int index) {
		if (index < 0 || index >= backer.size()) return;
		backer.remove(index);
		fireTableDataChanged();
	}

	@Override
	public void removeRows(int[] rows) {
		// sort the rows in reverse order, so that the row indices stay valid whilst later ones are removed
		Arrays.sort(rows);
				
		for (int i = rows.length - 1; i >= 0; i--) {
			if (rows[i] < 0 || rows[i] >= backer.size()) return;
			backer.remove(rows[i]);
		}
		// only fire the event when done, else the indexes won't correspond to rows properly.
		fireTableDataChanged();
	}

	@Override
	public void clear() {
		backer.clear();
		fireTableDataChanged();
	}
	
}
