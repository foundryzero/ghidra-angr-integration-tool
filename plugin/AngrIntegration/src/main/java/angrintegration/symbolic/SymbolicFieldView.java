package angrintegration.symbolic;

import java.awt.Dimension;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Insets;

import javax.swing.BorderFactory;
import javax.swing.JTextField;
import docking.util.GraphicsUtils;
import generic.theme.GColor;
import generic.theme.Gui;
import generic.theme.GThemeDefaults.Colors.Messages;

/**
 * A SymbolicField is just a JTextField with a convenient orange border so you know it's symbolic.
 */
public class SymbolicFieldView extends JTextField {

	/**
	 * The width of the symbolic value that will eventually come out of this field, in bits.
	 * 
	 *  e.g. a field for a register would probably have 16, 32, or 64 width, depending on the machine.
	 */
	private int fieldWidth;
	private String fieldName;
	
	private static final String FONT_ID = "font.input.hint";
	private int hintWidth;

	public SymbolicFieldView(int fieldWidth, String fieldName) {
		this(fieldWidth, fieldName, "");
	}

	public SymbolicFieldView(int fieldWidth, String fieldName, String text) {
		super(text);
				
		this.fieldName = fieldName;
		this.fieldWidth = fieldWidth;
		
		recomputeMetrics();
		
		var lineBorder = BorderFactory.createLineBorder(new GColor("color.palette.purple"));
		var padding = BorderFactory.createEmptyBorder(3, 7, 3, 7); // Values taken from the default Border in the default Ghidra theme
		
		this.setBorder(BorderFactory.createCompoundBorder(lineBorder, padding));
		this.setFont(Gui.getFont("font.panel.details.monospaced"));
	}
	
	/**
	 * Recomputes the offset to draw the hint text at. Should be called whenever the fieldName or fieldWidth are written to.
	 */
	public void recomputeMetrics() {
		FontMetrics fontMetrics = getFontMetrics(Gui.getFont(FONT_ID));
		var hintText = fieldName + " " + Integer.toString(fieldWidth);
		this.hintWidth = fontMetrics.stringWidth(hintText);
	}
	
	public int getFieldWidth() {
		return this.fieldWidth;
	}
	
	public String getFieldName() {
		return this.fieldName;
	}
	
	public void setFieldWidth(int val) {
		this.fieldWidth = val;
		recomputeMetrics();
	}
	
	public void setFieldName(String val) {
		this.fieldName = val;
		recomputeMetrics();
	}
	
	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		
		// Taken from IntegerTextField paintComponent 
		// which draws a similar hint
		
		var oldFont = g.getFont();
		g.setFont(Gui.getFont(FONT_ID));
		g.setColor(Messages.HINT);

		Dimension size = getSize();
		Insets insets = getInsets();
		int x;
		if (getHorizontalAlignment() == RIGHT) {
			x = insets.left;
		}
		else {
			x = size.width - insets.right - hintWidth;
		}
		int y = size.height - insets.bottom - 1;
		GraphicsUtils.drawString(this, g, fieldName + " " + Integer.toString(fieldWidth), x, y);
		g.setFont(oldFont);

	}
	
	
}
