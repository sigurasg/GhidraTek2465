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

import org.junit.jupiter.api.Test;

public class Disassembly6801Test extends DisassemblyCommonTest {
	public Disassembly6801Test() {
		super("MC6801:BE:16:default");
	}

	@Test
	public void ABX() {
		test(0x3A, "ABX");
	}

	@Test
	public void ADDD() {
		test(0xC3, "ADDD #0x1234", 0x12, 0x34);
		test(0xD3, "ADDD 0x00ab", 0xab);
		test(0xF3, "ADDD 0x1234", 0x12, 0x34);
		test(0xE3, "ADDD 0xab,X", 0xAB);
	}

	@Test
	public void PSHX() {
		test(0x3C, "PSHX");
	}

	@Test
	public void PULX() {
		test(0x38, "PULX");
	}

	@Test
	public void STD() {
		test(0xDD, "STD 0x00ab", 0xAB);
		test(0xFD, "STD 0x1234", 0x12, 0x34);
		test(0xED, "STD 0xab,X", 0xAB);
	}
}
