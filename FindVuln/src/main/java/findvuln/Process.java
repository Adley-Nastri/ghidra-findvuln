package findvuln;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

import ghidra.util.Msg;

public class Process {
	
	
	private static String output;
	
	
	
	public static String run(List<String> cmd, Object obj) throws IOException {

		
		
		var pB = new ProcessBuilder();
		
		
		pB.command(cmd);
		
		
		var process = pB.start();
		
		
		
		try (var reader = new BufferedReader(
	            new InputStreamReader(process.getInputStream())))
			{

		            String line;

		            while ((line = reader.readLine()) != null) 
		            {
		            
		               
		               if(!line.equals("")) {
		            	   output = line;
		            	   Msg.info(obj, output);
		               }
		               
		            }

		   }
		
		catch (IOException e) {
			Msg.info(obj, e);
			
		}
		
		return output;
	}

	
	public static String[] run(List<String> cmd) throws IOException {
		
		
		var pB = new ProcessBuilder();
		
		
		pB.command(cmd);
		
		
		pB.start();
		
		
		String[] arr = {"", ""};
		return arr;
	}
		
		


	public static String runWithBR(List<String> cmd) throws IOException {
		
		var pB = new ProcessBuilder();
		
		
		pB.command(cmd);
		
		
		var process = pB.start();
		
				
		
		try (var reader = new BufferedReader(
	            new InputStreamReader(process.getInputStream())))
			{

		            String line;

		            while ((line = reader.readLine()) != null) 
		            {
		            
		               
		               if(!line.equals("")) {
		            	   output = line;
		            	   
		               }
		               
		            }

		   }
		
		catch (IOException e) {
			
			
		}
		
		return output;
		
		
	}
}


