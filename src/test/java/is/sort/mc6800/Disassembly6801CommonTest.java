package is.sort.mc6800;

import org.junit.jupiter.api.Test;

public abstract class Disassembly6801CommonTest extends DisassemblyCommonTest {
	public Disassembly6801CommonTest(String lang) {
		super(lang);
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
	public void ASLD() {
		test(0x05, "ASLD");
	}

	@Override
	@Test
	public void JSR() {
		// Test the MC6800 variants.
		super.JSR();

		// The direct JSR is first present in the MC6801.
		test(0x9D, "JSR 0x00ab", 0xAB);
	}

	@Test
	public void LDD() {
		test(0xCC, "LDD #0x1234", 0x12, 0x34);
		test(0xDC, "LDD 0x00ab", 0xab);
		test(0xFC, "LDD 0x1234", 0x12, 0x34);
		test(0xEC, "LDD 0xab,X", 0xAB);
	}

	@Test
	public void LSRD() {
		test(0x04, "LSRD");
	}

	@Test
	public void MUL() {
		test(0x3D, "MUL");
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

	@Test
	public void SUBD() {
		test(0x83, "SUBD #0x1234", 0x12, 0x34);
		test(0x93, "SUBD 0x00ab", 0xab);
		test(0xB3, "SUBD 0x1234", 0x12, 0x34);
		test(0xA3, "SUBD 0xab,X", 0xAB);
	}

}