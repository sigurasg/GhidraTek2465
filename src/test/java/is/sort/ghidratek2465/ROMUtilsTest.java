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
import java.nio.ByteBuffer;

import org.junit.Test;

import ghidra.app.util.bin.ByteArrayProvider;

public class ROMUtilsTest {
	@Test
	public void getScopeKindTest() {
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x1625), ROMUtils.ScopeKind.TEK2465);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x1626), ROMUtils.ScopeKind.TEK2465);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x1627), ROMUtils.ScopeKind.TEK2465);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x1628), ROMUtils.ScopeKind.TEK2465);

		assertEquals(ROMUtils.scopeKindFromPartNumber(0x3302), ROMUtils.ScopeKind.TEK2465A);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x3303), ROMUtils.ScopeKind.TEK2465A);

		assertEquals(ROMUtils.scopeKindFromPartNumber(0x5370), ROMUtils.ScopeKind.TEK2465B);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x5371), ROMUtils.ScopeKind.TEK2465B);

		assertEquals(ROMUtils.scopeKindFromPartNumber(0x5876), ROMUtils.ScopeKind.TEK2465B_LATE);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x5877), ROMUtils.ScopeKind.TEK2465B_LATE);
	}

	@Test
	public void getScopeKindNameTest() {
		assertEquals("Tek2465", ROMUtils.getScopeKindName(ROMUtils.ScopeKind.TEK2465));
		assertEquals("Tek2465A", ROMUtils.getScopeKindName(ROMUtils.ScopeKind.TEK2465A));
		assertEquals("Tek2465B", ROMUtils.getScopeKindName(ROMUtils.ScopeKind.TEK2465B));
		assertEquals("Tek2465B SN>B050000",
			ROMUtils.getScopeKindName(ROMUtils.ScopeKind.TEK2465B_LATE));
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

	@Test
	public void checksumFullRangeTest() throws IOException {
		assertEquals(0xB47F, ROMUtils.checksumRange(getBytes(0x400), 0x0000, 0x0400));
	}

	public void checksumShortRangeTest() throws IOException {
		assertEquals(0xBCFF, ROMUtils.checksumRange(getBytes(0x400), 0x0000, 0x0300));
	}

	@Test(expected = IOException.class)
	public void checksumOutOfBounds() throws IOException {
		ROMUtils.checksumRange(getBytes(0x400), 0x0000, 0x0401);
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

	@Test
	public void doesntHaveValidHeaderAt() throws IOException {
		var data = getBytes(0x400);
		assertFalse(ROMUtils.hasValidHeaderAt(data, 0));
	}

	@Test
	public void hasValidHeaderAt() throws IOException {
		// Valid header, incorrect checksum.
		var data = getBytesWithHeader(0x8000,
			getHeader(0x1234, 0x3456, 0x1, ~0x1, 0x80, 0x0000, 0xFFFF, 0x0000, 0x00FF));

		ROMHeader h = new ROMHeader(data, 0);
		assertTrue(h.isValid());
		assertFalse(ROMUtils.hasValidHeaderAt(data, 0));

		// Valid header, correct checksum.
		data = getBytesWithHeader(0x8000,
			getHeader(0x42bc, 0x3456, 0x1, ~0x1, 0x80, 0x0000, 0xFFFF, 0x0000, 0x00FF));
		assertTrue(ROMUtils.hasValidHeaderAt(data, 0));

		// Valid header, correct checksum, incorrect tail checksum.
		data = getBytesWithHeader(0x8000,
			getHeader(0x6ebc, 0x3456, 0x1, ~0x1, 0x80, 0x1234, 0xFFFF, 0x0000, 0x00FF));
		assertFalse(ROMUtils.hasValidHeaderAt(data, 0));

		// Valid header, correct checksum and tail checksum.
		data = getBytesWithHeader(0x8000,
			getHeader(0xe330, 0x3456, 0x1, ~0x1, 0x80, 0x4675, 0xFFFF, 0x0000, 0x00FF));
		assertTrue(ROMUtils.hasValidHeaderAt(data, 0));
	}
}
