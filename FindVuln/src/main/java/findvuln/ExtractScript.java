package findvuln;

import java.io.IOException;

import java.util.Arrays;
import java.util.List;



public class ExtractScript {
	
	
	private static List<String> cmd;

	public static void main(String binLoc_In , String script_path , String outputFolder, Object obj, String OS) throws IOException {
		
	
		switch(OS) {
			
			case "wsl":
				//System properties
				cmd = Arrays.asList("cmd.exe", "/C", "wsl sh "+script_path+" " +binLoc_In+ " "+outputFolder);	
		
			case "win":
				
				cmd = Arrays.asList("cmd.exe", "/C", "" +script_path+" " +binLoc_In+ " "+outputFolder);
				
			case "lin":
				
				cmd = Arrays.asList("bash", "-c", "" +script_path+" " +binLoc_In+ " "+outputFolder);
		
		}
					
					
		Process.run(cmd, obj);			
					
			
	}
		
		
	
	public static String wslpathConvert(String pathIn, Object obj, char p) throws IOException {
		
			
		List<String> cmd = Arrays.asList("cmd.exe", "/C", "wsl wslpath -"+p+" "+pathIn);
		
		
		return Process.run(cmd, obj);
	}
	
}
