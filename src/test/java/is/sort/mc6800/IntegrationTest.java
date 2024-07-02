// Copyright 2024 Sigurdur Asgeirsson <siggi@sort.is>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package is.sort.mc6800;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import db.Transaction;
import generic.jar.ResourceFile;
import generic.test.AbstractGTest;
import generic.test.AbstractGenericTest;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.framework.GModule;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import utility.application.ApplicationLayout;

public abstract class IntegrationTest extends AbstractGenericTest {

	protected final Language language;
	protected final ProgramDB program;

	@Override
	protected ApplicationLayout createApplicationLayout() throws IOException {
		return new TestApplicationLayout(new File(AbstractGTest.getTestDirectoryPath()));
	}

	protected Address address(int addr) {
		return language.getDefaultSpace().getAddress(addr);
	}

	protected CodeUnit disassemble(byte[] bytes) {
		try (Transaction transaction = program.openTransaction("disassemble")) {
			ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
			// Create an overlay block.
			MemoryBlock block = program.getMemory()
					.createInitializedBlock("test", address(0), stream, bytes.length,
						TaskMonitor.DUMMY,
						true);

			Disassembler disassembler =
				Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null);
			disassembler.disassemble(block.getStart(),
				program.getMemory().getLoadedAndInitializedAddressSet());
			CodeUnit ret = program.getCodeManager().getCodeUnitAt(block.getStart());
			transaction.commit();
			return ret;
		}
		catch (Exception e) {
			return null;
		}
	}

	public IntegrationTest() throws IOException {
		SleighLanguageProvider provider = SleighLanguageProvider.getSleighLanguageProvider();
		this.language = provider.getLanguage(new LanguageID("MC6800:BE:16:default"));
		this.program = new ProgramDB("test", language, language.getDefaultCompilerSpec(), this);
	}

	// This is necessary to inject the build directory into the application layout.
	private class TestApplicationLayout extends GhidraTestApplicationLayout {
		public TestApplicationLayout(File path) throws IOException {
			super(path);
		}

		@Override
		public Map<String, GModule> findGhidraModules() throws IOException {
			var ret = new HashMap<String, GModule>(super.findGhidraModules());

			ret.put("6800", new GModule(applicationRootDirs, new ResourceFile("./build")));
			return ret;
		}
	}
}
