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

package is.sort.ghidratek2465;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.HexFormat;

import org.junit.Test;

import ghidra.app.util.bin.ByteArrayProvider;

public class ROMHeaderTest {
	static ROMHeader fromString(String str, int offset) throws IOException {
		return new ROMHeader(
			new ByteArrayProvider(HexFormat.of().parseHex(str)),
			offset);
	}

	@Test
	public void validHeaderTest() throws IOException {
		ROMHeader h = fromString(
			"1234" +	// Checksum.
				"3302" +  	// Part number.
				"06F9" + 	// Version and complement.
				"80" +		// Load address.
				"CC00" +  	// Load address and unknown.
				"FFFF" + 	// ROM end.
				"0000" +  	// Next ROM.
				"00FF", 	// Trailer.
			0);

		assertEquals(h.checksum, 0x1234);
		assertEquals(h.partNumber, 0x3302);
		assertEquals(h.version, 0x06);
		assertEquals(h.versionCompl, 0xF9);
		assertEquals(h.loadAddr, 0x80);
		assertEquals(h.romEnd, 0xFFFF);
		assertEquals(h.nextRom, 0x0000);
		assertEquals(h.signature, 0x00FF);

		assertTrue(h.isValid());
		assertEquals(h.getLoadAddress(), 0x8000);
		assertEquals(h.getByteSize(), 0x8000);
	}

	@Test
	public void invalidHeaderTest() throws IOException {
		ROMHeader h = fromString(
			"12343302" +
				"07FD" + 	// Invalid version complement.
				"80CC00FFFF000000FF",
			0);
		assertFalse(h.isValid());

		h = fromString(
			"1234330207F980CC00FFFF0000" +
				"00FE",  // Invalid signature.
			0);
		assertFalse(h.isValid());
	}
}
