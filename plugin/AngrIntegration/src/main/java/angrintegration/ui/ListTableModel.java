package angrintegration.ui;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.table.AbstractTableModel;

/**
 * An EditableTableModel providing a simple one-column table of a single data type.
 * @param <T> The data type in the table's single column.
 */
public class ListTableModel<T> extends AbstractTableModel implements EditableTableModel<T> {
	
	private List<T> backer; // backing storage for the actual table elements
	private T defaultT;
	
	private String header;
	
	/**
	 * Create a new ListTableModel.
	 * @param defaultT a reasonable default element to be used when a new row is added
	 * @param header the column header for the table's single column
	 */
	public ListTableModel(T defaultT, String header) {
		this(new ArrayList<T>(), defaultT, header);
	}
	
	/**
	 * Create a new ListTableModel with default column header (implementation dependent, but most likely 'A')
	 * @param defaultT a reasonable default element to be used when a new row is added
	 */
	public ListTableModel(T defaultT) {
		this(new ArrayList<T>(), defaultT, null);
	}
	
	/**
	 * Create a new ListTableModel from an already existing list.
	 * @param backer the list containing table elemenets to use
	 * @param defaultT a reasonable default element to be used when a new row is added
	 * @param header the column header for the table's single column
	 */
	public ListTableModel(List<T> backer, T defaultT, String header) {
		this.backer = backer;
		this.defaultT = defaultT;
		this.header = header;
	}
	
	@Override
	public String getColumnName(int column) {
		if (header != null) {
			return header;
		}
		return super.getColumnName(column);
	}

	@Override
	public int getRowCount() {
		return backer.size();
	}

	@Override
	public int getColumnCount() {
		return 1;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		return backer.get(rowIndex);
	}
	
	@SuppressWarnings("unchecked") // type erasure means instanceof T won't work
	@Override
	public void setValueAt(Object value, int row, int col) {
		backer.set(row, (T) value);
		fireTableCellUpdated(row, col);
	}
	
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return true;
	}

	@Override
	public void addRow() {
		this.addRow(defaultT);
	}
	
	@Override
	public void addRow(T value) {
		backer.add(value);
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
	public List<T> getRows() {
		return backer;
	}

	@Override
	public void clear() {
		backer.clear();
	}
	
}