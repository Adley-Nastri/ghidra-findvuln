package findvuln.CVEScanner.checkers;

import java.util.List;

public class Busybox extends Checker{
	
	public Busybox() {
		super();
		this.CONTAINS_PATTERNS = List.of();
		this.FILENAME_PATTERNS = List.of("busybox");
		this.VERSION_PATTERNS  = List.of("BusyBox v([0-9]+\\.[0-9]+\\.[0-9]+)");
		this.VENDOR_PRODUCT    = List.of("busybox", "busybox");
	}
	
}