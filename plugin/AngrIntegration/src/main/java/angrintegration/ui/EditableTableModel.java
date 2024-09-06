package angrintegration.ui;

import java.util.List;

import javax.swing.table.TableModel;

/**
 * Implement this to make your model compatible with EditableTables.
 * @param <T> The row type of the table
 */
public interface EditableTableModel<T> extends TableModel {
	/**
	 * Get a list of each row of the table.
	 * 
	 * Note: the returned list is NOT guaranteed to be independent from the backing of the table itself!
	 * If the whole array is needed for storage elsewhere, consider copying the returned list.
	 * 
	 * @return a list of rows of the table.
	 */
	public List<T> getRows();
	
	/**
	 * Add a row with a sensible default value.
	 * (This will be invoked when the plus button is activated on the parent EditableTable)
	 */
	public void addRow();
	
	/**
	 * Add a row with the provided value.
	 * @param value the row to add
	 */
	public void addRow(T value);
	
	/**
	 * Remove a row at the given index.
	 * @param index the index of the row to remove
	 */
	public void removeRow(int index);
	
	/**
	 * Remove rows at the given indices.
	 * 
	 * Implementation note: you may wish to reverse-sort this array so that 
	 * rows can be removed from a backing list without recalculating indices.
	 * @param rows the rows to remove.
	 */
	public void removeRows(int[] rows);
	
	/**
	 * Removes all rows from the table.
	 */
	public void clear();
}