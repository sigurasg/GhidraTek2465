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

import java.io.IOException;

import org.junit.Test;

import db.Transaction;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EmulatorTest extends IntegrationTest {
	public EmulatorTest() throws IOException {
		try (Transaction transaction = program.openTransaction("test")) {
			program.getMemory().createUninitializedBlock("ram", address(0x0000), 0x10000, false);
			transaction.commit();
		}
		catch (Exception e) {
		}
	}

	protected void setA(int value) {
		emulator.writeRegister("A", value);
	}

	protected void setB(int value) {
		emulator.writeRegister("B", value);
	}

	protected void setCC(int value) {
		emulator.writeRegister("CC", value);
	}

	protected void setX(int value) {
		emulator.writeRegister("X", value);
	}

	protected void setS(int value) {
		emulator.writeRegister("S", value);
	}

	protected void setPC(int value) {
		emulator.writeRegister("PC", value);
	}

	protected int getA() {
		return emulator.readRegister("A").intValue();
	}

	protected int getB() {
		return emulator.readRegister("B").intValue();
	}

	protected int getCC() {
		return emulator.readRegister("CC").intValue();
	}

	protected int getX() {
		return emulator.readRegister("X").intValue();
	}

	protected int getS() {
		return emulator.readRegister("S").intValue();
	}

	protected int getPC() {
		return emulator.readRegister("PC").intValue();
	}

	@Test
	public void NOP() throws CancelledException {
		emulator = new EmulatorHelper(program);
		emulator.setMemoryFaultHandler(new FailOnMemoryFault());

		setA(0x00);
		setB(0x00);
		setCC(0x00);
		setX(0x0000);
		setS(0x0800);
		setPC(0x0000);

		emulator.writeMemory(address(0x0000), new byte[] { (byte) 0x01 });
		emulator.step(TaskMonitor.DUMMY);

		assertEquals(getA(), 0x00);
		assertEquals(getB(), 0x00);
		assertEquals(getCC(), 0x00);
		assertEquals(getX(), 0x0000);
		assertEquals(getS(), 0x0800);
		assertEquals(0x0001, getPC());
	}

	private class FailOnMemoryFault implements MemoryFaultHandler {
		@Override
		public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset) {
			return false;
		}

		@Override
		public boolean unknownAddress(Address address, boolean write) {
			return false;
		}

	}

	private EmulatorHelper emulator;
}
