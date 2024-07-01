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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

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

public class DisassemblyTest extends AbstractGenericTest {
	public DisassemblyTest() {
		SleighLanguageProvider provider = SleighLanguageProvider.getSleighLanguageProvider();
		language = provider.getLanguage(new LanguageID("MC6800:BE:16:default"));
	}

	@Test
	public void languageFoundTest() {
		assertNotEquals(language, null);
	}

	// The instructions are tested in the order of appearance in the
	// Motorola M6800 Programming Reference Manual.
	// http://www.bitsavers.org/components/motorola/6800/Motorola_M6800_Programming_Reference_Manual_M68PRM(D)_Nov76.pdf

	@Test
	public void ABA() {
		test(0x1B, "ABA");
	}

	@Test
	public void ADC() {
		test(0x89, "ADCA #0xa", 0x0A);
		test(0x99, "ADCA 0x000a", 0x0A);
		test(0xB9, "ADCA 0x1234", 0x12, 0x34);
		test(0xA9, "ADCA 0xa,X", 0x0A);

		test(0xC9, "ADCB #0xa", 0x0A);
		test(0xD9, "ADCB 0x000a", 0x0A);
		test(0xF9, "ADCB 0x1234", 0x12, 0x34);
		test(0xE9, "ADCB 0xa,X", 0x0A);
	}

	@Test
	public void ADD() {
		test(0x8B, "ADDA #0xa", 0x0A);
		test(0x9B, "ADDA 0x000a", 0x0A);
		test(0xBB, "ADDA 0x1234", 0x12, 0x34);
		test(0xAB, "ADDA 0xa,X", 0x0A);

		test(0xCB, "ADDB #0xa", 0x0A);
		test(0xDB, "ADDB 0x000a", 0x0A);
		test(0xFB, "ADDB 0x1234", 0x12, 0x34);
		test(0xEB, "ADDB 0xa,X", 0x0A);
	}

	@Test
	public void AND() {
		test(0x84, "ANDA #0xa", 0x0A);
		test(0x94, "ANDA 0x000a", 0x0A);
		test(0xB4, "ANDA 0x1234", 0x12, 0x34);
		test(0xA4, "ANDA 0xa,X", 0x0A);

		test(0xC4, "ANDB #0xa", 0x0A);
		test(0xD4, "ANDB 0x000a", 0x0A);
		test(0xF4, "ANDB 0x1234", 0x12, 0x34);
		test(0xE4, "ANDB 0xa,X", 0x0A);
	}

	@Test
	public void ASL() {
		test(0x48, "ASLA");
		test(0x58, "ASLB");
		test(0x78, "ASL 0x1234", 0x12, 0x34);
		test(0x68, "ASL 0x12,X", 0x12);
	}

	@Test
	public void ASR() {
		test(0x47, "ASRA");
		test(0x57, "ASRB");
		test(0x77, "ASR 0x1234", 0x12, 0x34);
		test(0x67, "ASR 0x12,X", 0x12);
	}

	@Test
	public void BCC() {
		test(0x24, "BCC 0x0022", 0x20);
	}

	@Test
	public void BCS() {
		test(0x25, "BCS 0x0022", 0x20);
	}

	@Test
	public void BEQ() {
		test(0x27, "BEQ 0x0022", 0x20);
	}

	@Test
	public void BGE() {
		test(0x2C, "BGE 0x0022", 0x20);
	}

	@Test
	public void BGT() {
		test(0x2E, "BGT 0x0022", 0x20);
	}

	@Test
	public void BHI() {
		test(0x22, "BHI 0x0022", 0x20);
	}

	@Test
	public void BIT() {
		test(0x85, "BITA #0xab", 0xAB);
		test(0x95, "BITA 0x00ab", 0xAB);
		test(0xB5, "BITA 0x1234", 0x12, 0x34);
		test(0xA5, "BITA 0xab,X", 0xAB);

		test(0xC5, "BITB #0xab", 0xAB);
		test(0xD5, "BITB 0x00ab", 0xAB);
		test(0xF5, "BITB 0x1234", 0x12, 0x34);
		test(0xE5, "BITB 0xab,X", 0xAB);
	}

	@Test
	public void BLE() {
		test(0x2F, "BLE 0x0022", 0x20);
	}

	@Test
	public void BLS() {
		test(0x23, "BLS 0x0022", 0x20);
	}

	@Test
	public void BLT() {
		test(0x2D, "BLT 0x0022", 0x20);
	}

	@Test
	public void BMI() {
		test(0x2B, "BMI 0x0022", 0x20);
	}

	@Test
	public void BNE() {
		test(0x26, "BNE 0x0022", 0x20);
	}

	@Test
	public void BPL() {
		test(0x2A, "BPL 0x0022", 0x20);
	}

	@Test
	public void BRA() {
		test(0x20, "BRA 0x0022", 0x20);
	}

	@Test
	public void BSR() {
		test(0x8D, "BSR 0x0022", 0x20);
	}

	@Test
	public void BVC() {
		test(0x28, "BVC 0x0022", 0x20);
	}

	@Test
	public void BVS() {
		test(0x29, "BVS 0x0022", 0x20);
	}

	@Test
	public void CBA() {
		test(0x11, "CBA");
	}

	@Test
	public void CLC() {
		test(0x0C, "CLC");
	}

	@Test
	public void CLI() {
		test(0x0E, "CLI");
	}

	@Test
	public void CLR() {
		test(0x4F, "CLRA");
		test(0x5F, "CLRB");
		test(0x7F, "CLR 0x1234", 0x12, 0x34);
		test(0x6F, "CLR 0x12,X", 0x12);
	}

	@Test
	public void CLV() {
		test(0x0A, "CLV");
	}

	// TODO(siggi): Test the rest of the instruction set.

	@Test
	public void NOP() {
		test(0x01, "NOP");
	}

	private void test(int opCode, String expected, int... args) {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();

		stream.write(opCode);
		for (int arg : args) {
			stream.write(arg);
		}

		CodeUnit codeUnit = disassemble(stream.toByteArray());
		assertNotNull(codeUnit);
		assertEquals(expected, codeUnit.toString());
	}

	@Override
	protected ApplicationLayout createApplicationLayout() throws IOException {
		return new TestApplicationLayout(new File(AbstractGTest.getTestDirectoryPath()));
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

	private Address address(int addr) {
		return language.getDefaultSpace().getAddress(addr);
	}

	private CodeUnit disassemble(byte[] bytes) {
		ProgramDB program;
		try {
			program = new ProgramDB("test", language, language.getDefaultCompilerSpec(), this);
		}
		catch (IOException e) {
			return null;
		}

		try (Transaction transaction = program.openTransaction("disassemble")) {
			ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
			MemoryBlock block = program.getMemory()
					.createInitializedBlock("test", address(0), stream, bytes.length,
						TaskMonitor.DUMMY,
						false);

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

	protected final Language language;
}
