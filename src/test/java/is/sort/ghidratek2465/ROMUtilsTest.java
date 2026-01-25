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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;

import ghidra.app.util.bin.ByteArrayProvider;

public class ROMUtilsTest {
	@Test
	public void getScopeKindTest() {
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x1625), ScopeKind.TEK2465);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x1626), ScopeKind.TEK2465);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x1627), ScopeKind.TEK2465);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x1628), ScopeKind.TEK2465);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x1994), ScopeKind.TEK2465);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x1995), ScopeKind.TEK2465);

		assertEquals(ROMUtils.scopeKindFromPartNumber(0x3302), ScopeKind.TEK2465A);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x3303), ScopeKind.TEK2465A);

		assertEquals(ROMUtils.scopeKindFromPartNumber(0x5370), ScopeKind.TEK2465B);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x5371), ScopeKind.TEK2465B);

		assertEquals(ROMUtils.scopeKindFromPartNumber(0x5876), ScopeKind.TEK2465B_LATE);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x5877), ScopeKind.TEK2465B_LATE);
	}

	@Test
	public void getScopeKindNameTest() {
		assertEquals("Tek2465", ROMUtils.getScopeKindName(ScopeKind.TEK2465));
		assertEquals("Tek2465A", ROMUtils.getScopeKindName(ScopeKind.TEK2465A));
		assertEquals("Tek2465B", ROMUtils.getScopeKindName(ScopeKind.TEK2465B));
		assertEquals("Tek2465B SN>B050000",
			ROMUtils.getScopeKindName(ScopeKind.TEK2465B_LATE));
	}

	@Test
	public void checksumFullRangeTest() throws IOException {
		assertEquals(0xB47F, ROMUtils.checksumRange(getBytes(0x400), 0x0000, 0x0400));
	}

	public void checksumShortRangeTest() throws IOException {
		assertEquals(0xBCFF, ROMUtils.checksumRange(getBytes(0x400), 0x0000, 0x0300));
	}

	@Test
	public void checksumOutOfBounds() throws IOException {
		assertThrows(IOException.class,
			() -> ROMUtils.checksumRange(getBytes(0x400), 0x0000, 0x0401));
	}

	@Test
	public void hasValidHeaderAt() throws IOException {
		var data = getBytes(0x400);
		assertFalse(ROMUtils.hasValidHeaderAt(data, 0));

		// Valid header, incorrect checksum.
		data = getIncorrectChecksumRom();
		// Make sure the header is valid.
		assertTrue(new ROMHeader(data, 0).isValid());
		assertFalse(ROMUtils.hasValidHeaderAt(data, 0));

		// Valid header, correct checksum.
		data = getCorrectChecksumRom();
		assertTrue(ROMUtils.hasValidHeaderAt(data, 0));

/*
 * No tail header validation for now :(.
 *
		// Valid header, correct checksum, incorrect tail checksum.
		data = getIncorrectTailChecksumRom();
		assertFalse(ROMUtils.hasValidHeaderAt(data, 0));

		// Valid header, correct checksum and tail checksum.
		data = getCorrectTailChecksumRom();
		assertTrue(ROMUtils.hasValidHeaderAt(data, 0));
 */
	}

	@Test
	public void findValidRomHeadersTest() throws IOException {
		var data = getIncorrectChecksumRom();
		assertArrayEquals(new int[0], ROMUtils.findValidRomHeaders(data));

		// Valid header, correct checksum and tail checksum.
		data = getCorrectTailChecksumRom();

		assertArrayEquals(new int[] { 0x0000 }, ROMUtils.findValidRomHeaders(data));

		// Pad the ROM file with some bytes.
		byte[] concat = new byte[(int) (data.length() + 0x2000)];
		ByteBuffer buffer = ByteBuffer.wrap(concat);
		buffer.put(getByteArray(0x2000));
		buffer.put(data.readBytes(0, data.length()));

		assertArrayEquals(new int[] { 0x2000 },
			ROMUtils.findValidRomHeaders(new ByteArrayProvider(concat)));
	}

	@Test
	public void getKnownFunctionsForROMTest() throws IOException {
		// Known 2465A ROM versions.
		assertEquals(3, ROMUtils.getKnownFunctions(0x3302, 0x04).length);
		assertEquals(3, ROMUtils.getKnownFunctions(0x3303, 0x04).length);

		assertEquals(3, ROMUtils.getKnownFunctions(0x3302, 0x06).length);
		assertEquals(3, ROMUtils.getKnownFunctions(0x3303, 0x06).length);

		assertEquals(3, ROMUtils.getKnownFunctions(0x3302, 0x07).length);
		assertEquals(3, ROMUtils.getKnownFunctions(0x3303, 0x07).length);

		assertEquals(3, ROMUtils.getKnownFunctions(0x3302, 0x09).length);
		assertEquals(3, ROMUtils.getKnownFunctions(0x3303, 0x09).length);

		// Know 2465B early version.
		assertEquals(8, ROMUtils.getKnownFunctions(0x5370, 0x06).length);
		assertEquals(12, ROMUtils.getKnownFunctions(0x5371, 0x06).length);

		assertEquals(8, ROMUtils.getKnownFunctions(0x5370, 0x07).length);
		assertEquals(12, ROMUtils.getKnownFunctions(0x5371, 0x07).length);

		assertEquals(8, ROMUtils.getKnownFunctions(0x5370, 0x10).length);
		assertEquals(12, ROMUtils.getKnownFunctions(0x5371, 0x10).length);

		// Known 2465B late versions.
		assertEquals(8, ROMUtils.getKnownFunctions(0x5876, 1).length);
	}

	static private byte[] getByteArray(int byte_len) {
		byte[] data = new byte[byte_len];
		for (int i = 0; i < data.length; ++i) {
			data[i] = (byte) i;
		}
		return data;
	}

	static private ByteArrayProvider getBytes(int byte_len) {
		return new ByteArrayProvider(getByteArray(byte_len));
	}

	static private ByteArrayProvider getBytesWithHeader(int byte_len, byte[] header) {
		byte[] data = new byte[byte_len];
		ByteBuffer buffer = ByteBuffer.wrap(data);
		buffer.put(header);
		buffer.put(getByteArray(byte_len - header.length));
		return new ByteArrayProvider(data);
	}

	static private byte[] getHeader(
			int checksum,
			int part_number,
			int version,
			int version_compl,
			int load_addr,
			int tail_checksum,
			int rom_end,
			int next_rom,
			int zero_effeff) {
		byte[] header = {
			(byte) (checksum >> 8), (byte) (checksum),
			(byte) (part_number >> 8), (byte) (part_number),
			(byte) version,
			(byte) version_compl,
			(byte) load_addr,
			(byte) (tail_checksum >> 8), (byte) (tail_checksum),
			(byte) (rom_end >> 8), (byte) (rom_end),
			(byte) (next_rom >> 8), (byte) (next_rom),
			(byte) (zero_effeff >> 8), (byte) (zero_effeff)
		};
		return header;
	}

	private ByteArrayProvider getCorrectTailChecksumRom() {
		return getBytesWithHeader(0x8000,
			getHeader(0xe330, 0x3456, 0x1, ~0x1, 0x80, 0x4675, 0xFFFF, 0x0000, 0x00FF));
	}

	/*
	 * Unused for now as the tail header is not checked.
	 *
	private ByteArrayProvider getIncorrectTailChecksumRom() {
		return getBytesWithHeader(0x8000,
			getHeader(0x6ebc, 0x3456, 0x1, ~0x1, 0x80, 0x1234, 0xFFFF, 0x0000, 0x00FF));
	}
	 */

	private ByteArrayProvider getCorrectChecksumRom() {
		return getBytesWithHeader(0x8000,
			getHeader(0x42bc, 0x3456, 0x1, ~0x1, 0x80, 0x0000, 0xFFFF, 0x0000, 0x00FF));
	}

	private ByteArrayProvider getIncorrectChecksumRom() {
		var data = getBytesWithHeader(0x8000,
			getHeader(0x1234, 0x3456, 0x1, ~0x1, 0x80, 0x0000, 0xFFFF, 0x0000, 0x00FF));
		return data;
	}
}
