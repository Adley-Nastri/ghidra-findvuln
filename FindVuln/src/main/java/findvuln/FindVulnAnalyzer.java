/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package findvuln;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

import findvuln.CVEScanner.CVE_Scanner;
import findvuln.CVEScanner.VulnFile;
import generic.jar.ResourceFile;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;



/**
 * This analyzer searches through binaries within firmware and marks them with
 * potential CVEs based on common constants
 */
public class FindVulnAnalyzer extends AbstractAnalyzer {

	
	
    Connection cve_scanner_conn ;

	public FindVulnAnalyzer() {
		super("Find Vuln Extractor", "Extract firmware to then be used in finding CVEs within firmware binaries",
				AnalyzerType.BYTE_ANALYZER);
		
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		// We're on by default
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		// We can analyze anything with bytes!
		return true;
	}

	@Override

	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		
		
		try {
			
			

			Msg.info(this, program.getDomainFile().getParent());

			ProjectLocator pl = program.getDomainFile().getProjectLocator();

			Msg.info(this, "PL exists? " + pl.exists());

			Msg.info(this, program.getExecutablePath());

			

			// OKAY wslpath is what ya need to use :)

			// WSLmode and Windows mode, Enumerations maybe ?
			
			if (program.getExecutablePath().substring(0, 6).equals("//wsl$")) {

				ResourceFile rf = Application.getModuleFile("FindVuln", "os/linux64/extract.sh");
				
				

				Msg.info(this, "WE are using WSL mode");
				String bin = ExtractScript.wslpathConvert(program.getExecutablePath(), this, 'a');
				String script_path = ExtractScript.wslpathConvert("\"" + rf.getAbsolutePath() + "\"", this, 'u');

				String dir = "tmp";
				
				ExtractScript.main(bin, script_path, "/"+dir, this, "wsl");
				
				
				
				
				cve_scanner_conn = CVE_Scanner.main(new File("\\\\wsl$\\Ubuntu\\"+dir+"\\_"+program.getName()+".extracted\\"));
				
				
				
				CVE_Scanner.cve_map.entrySet().stream().distinct().forEach(e -> Msg.debug(this, e.getKey() + " " +e.getValue().version + " " + e.getValue().cve_list));
				
				
				ArrayList<String> unique_cves = new ArrayList<String>();
				
				
				
				
				for(var item : CVE_Scanner.cve_map.entrySet()) {
					
					
					
					
					unique_cves.addAll(item.getValue().cve_list);
					
					
					
					
					
				}
				
				Set<String> set_ = new HashSet<>(unique_cves);
				
				unique_cves.clear();
				unique_cves.addAll(set_);
				
				
				int cve_count = unique_cves.size();
				
				
				
				
				//List affected files
				Msg.debug(this, "\nAffected Files\n");
				CVE_Scanner.cve_map.entrySet().stream().distinct().forEach(e -> Msg.debug(this, e.getKey() +  " " + e.getValue().filepath));
				
				
				Msg.debug(this, "\nTotal Unique CVEs: "+ cve_count);
				
				//CVE_Scanner.cve_map.entrySet().stream().distinct().forEach(e -> e.getValue().size());
				
			}

//			if (!program.getExecutablePath().substring(0, 6).equals("//wsl$")) {
//
//				ResourceFile rf = Application.getModuleFile("FindVuln", "os/win64/extract.bat");
//
//				String bin = program.getExecutablePath();
//				String script_path = rf.getAbsolutePath();
//				
//				ExtractScript.main(bin, script_path, "C:\\CN6103", this, "win");
//			}
			
			
			//CVEScanner on folder returned by binwalk script (rfs_loc)
				
			//Report CVE information for all found and supported binaries
			
			
			
			

			/*
			 * Move all extracted binaries into the project. Create sub folders within the
			 * project Look within the file system and run script on each binary, possibly
			 * consider threading
			 * 
			 * 
			 * 
			 * Example: Recursively run scripts and analysis over all the binaries in the
			 * folder folderTwo of the existing project named Project2
			 * 
			 * analyzeHeadless /Users/user/ghidra/Projects Project2/folderTwo -scriptPath
			 * /user/scripts -preScript FixupPreScript.java -process -recursive
			 * 
			 * 
			 * An another note find the root-fs location (maybe dropped by the shell script
			 * and into a txt file) and do a search from there and then perform analysis on
			 * each binary recursively Probably look into the /tmp folder and do all the
			 * magic from there :)
			 * 
			 * 
			 * 
			 * 
			 * NEW IDEA require extraction to occur first , with ghidraScript. Load files
			 * into the project folder VulnAnalyzer disabled until then. Analyser will
			 * recursively
			 * 
			 * NEXT find a way to import extracted files and use navigation to go them.
			 * 
			 * 
			 * USE YARA - Not doing anymore due to time constraints and not that relevant
			 * 
			 */

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();

		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return true;
	}

	
	
	
	@Override
	public void analysisEnded(Program program) {
		
		super.analysisEnded(program);
	}
}
