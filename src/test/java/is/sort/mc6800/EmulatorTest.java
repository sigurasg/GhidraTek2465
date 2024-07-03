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

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class EmulatorTest extends AbstractEmulatorTest {
	public EmulatorTest() {
		super();
	}

	@Test
	public void NOP() {
		setA(0x00);
		setB(0x00);
		setCC(0x00);
		setX(0x0000);
		setS(0x0800);

		write(0x0000, 0x01);
		stepFrom(0x000);

		assertEquals(getA(), 0x00);
		assertEquals(getB(), 0x00);
		assertEquals(getCC(), 0x00);
		assertEquals(getX(), 0x0000);
		assertEquals(getS(), 0x0800);
		assertEquals(0x0001, getPC());
	}

	@Test
	public void CPX() {
		write(0x0000, 0x8C, 0x12, 0x34);

		// Test the equals case.
		setX(0x1234);
		setCC(0x00);
		stepFrom(0x0000);
		assertEquals(0x1234, getX());
		assertEquals(CC.Z, getCC());

		// Test the negative overflow case, as per the
		// programming manual the carry flag is
		// unaffected.
		setX(0x1233);
		setCC(0x00);
		stepFrom(0x0000);
		assertEquals(CC.N, getCC());
	}
}
