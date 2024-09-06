package angrintegration.ui;

import java.awt.Dimension;
import java.awt.LayoutManager;
import java.awt.Rectangle;

import javax.swing.JPanel;
import javax.swing.Scrollable;

/**
 * A simple JPanel extension telling a parent JScrollPanel not to scroll horizontally.
 */
public class ForceNoHorizontalScrollPanel extends JPanel implements Scrollable {

	public ForceNoHorizontalScrollPanel(LayoutManager layout) {
		super(layout);
	}

	@Override
	public Dimension getPreferredScrollableViewportSize() {
		return getPreferredSize();
	}

	@Override
	public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
		return 10;
	}

	@Override
	public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
		return 10;
	}

	@Override
	public boolean getScrollableTracksViewportWidth() {
		return true; // always force the panel width to the scrollable viewport width
	}

	@Override
	public boolean getScrollableTracksViewportHeight() {
		return false;
	}
	
}
