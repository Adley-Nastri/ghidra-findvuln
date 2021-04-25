package findvuln.CVEScanner;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import findvuln.Process;

public class Util {

	public static String regex_find(String[] lines,  List<String> VERSION_PATTERNS) {
		
		String new_guess = "";
		
		for (String line : lines) {
			
			for (String pattern : VERSION_PATTERNS) {
				Pattern pat = Pattern.compile(pattern);
				Matcher mat = pat.matcher(line);
				
				
				
				
				boolean match = mat.find();
				
				if (match) {
					String new_guess2 = mat.group(1).trim();
					if(new_guess2.length() > new_guess.length()) {
						new_guess = new_guess2 ;
					}
					
					
				}
			}
		}
		if(new_guess != "") {
			new_guess = new_guess.replace("_", ".");
			return new_guess.replace("-", ".");
		}
		else {
			return "UNKNOWN";
		}
		
	}
	
	
	
	
public static String wslpathConvert(String pathIn, char p) throws IOException {
		
			
		
		
		List<String> cmd = Arrays.asList("cmd.exe", "/C", "wsl wslpath -"+p+" "+pathIn);
		
		
		return Process.runWithBR(cmd);
	}
	
	
	public static String[] Strings(File file) throws IOException {
		
		
		
		List<String> cmd;		
		
		String converted = wslpathConvert(file.getAbsolutePath().replace("\\", "\\\\"), 'a');
		String converted2 = wslpathConvert(converted, 'w');
		
		cmd = Arrays.asList("cmd.exe", "/C", "wsl strings", converted , ">",converted2+ ".strings");
		
		
		Process.run(cmd);
		
		
		
		ArrayList<String> al = new ArrayList<String>();
		
		
		try (var reader = new BufferedReader(
				
				
				new FileReader(file) 
				
				
				))
		{
			String line;
			
			while ((line = reader.readLine()) != null) {
				
				al.add(line);
			}
			
		}
		
		catch (IOException e) {
			System.out.println(e);
		}
		
		
		String[] arr = al.toArray(new String[al.size()]);
		
		cmd = Arrays.asList("cmd.exe", "/C", "wsl rm", converted+ ".strings");
		
		Process.run(cmd);
		
		return arr;
		
		
		
	}
		
		
		
	
	
	
}
