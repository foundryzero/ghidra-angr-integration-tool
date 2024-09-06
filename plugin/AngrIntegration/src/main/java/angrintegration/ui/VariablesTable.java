package angrintegration.ui;

import java.awt.Color;
import java.awt.Component;
import javax.swing.BorderFactory;
import javax.swing.JTable;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;

import angrintegration.symbolic.SymbolicFieldView;
import docking.widgets.table.GTable;
import docking.widgets.table.GTableTextCellEditor;
import generic.theme.GColor;

/**
 * A VariablesTable is an EditableTable with the four fields to define variables.
 */
public class VariablesTable extends EditableTable {
	
	public VariablesTable(String title, VariablesTableModel model) {
		super(title, model, new GTable(model) {
			@Override
			public TableCellRenderer getCellRenderer(int row, int col) {
				if (col == VariablesTableModel.VALUE_COL_INDEX) {
					return new TableSymbolicFieldView(-1, "");
				}
				
				return super.getCellRenderer(row, col);
			}
			
			@Override
			public TableCellEditor getCellEditor(int row, int col) {
				if (col == VariablesTableModel.VALUE_COL_INDEX) {
					var editor = new SymbolicFieldView(0, "");
					editor.setFieldName((String) getModel().getValueAt(row, VariablesTableModel.NAME_COL_INDEX));
					editor.setFieldWidth((int) getModel().getValueAt(row, VariablesTableModel.LENGTH_COL_INDEX));

					return new GTableTextCellEditor(editor);
				}
				
				if (col == VariablesTableModel.LENGTH_COL_INDEX) {
					
				}
				
				return super.getCellEditor(row, col);
			}
		});
	}
	
	private static class TableSymbolicFieldView extends SymbolicFieldView implements TableCellRenderer {
		
		Color defaultBackground;
		Color selectedBackground;

		public TableSymbolicFieldView(int fieldWidth, String fieldName) {
			this(fieldWidth, fieldName, "");
		}
		
		

		public TableSymbolicFieldView(int fieldWidth, String fieldName, String text) {
			super(fieldWidth, fieldName, text);
			
			this.setBorder(BorderFactory.createMatteBorder(0, 1, 1, 1, new GColor("color.palette.purple")));
			this.defaultBackground = getBackground();
			this.selectedBackground = getSelectionColor();
		}
		
		Component getTableComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
			this.setText((String) value);
			this.setFieldName((String) table.getModel().getValueAt(row, VariablesTableModel.NAME_COL_INDEX));
			this.setFieldWidth((int) table.getModel().getValueAt(row, VariablesTableModel.LENGTH_COL_INDEX));
			
			if (isSelected) {
				this.setBackground(selectedBackground);
			} else {
				this.setBackground(defaultBackground);
			}
			return this;		}


		@Override
		public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
				int row, int column) {
			return getTableComponent(table, value, isSelected, hasFocus, row, column);
		}
		
	}

}
