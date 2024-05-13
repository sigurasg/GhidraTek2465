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

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;

public class ROMUtils {
	// TODO(siggi): Search ROMs for valid headers and return their location.

	// The recognized scope kinds.
	public enum ScopeKind {
		UNKNOWN, TEK2465, TEK2465A, TEK2465B, TEK2465B_LATE,
	}

	// Find the scope kind from part number.
	public static ScopeKind scopeKindFromPartNumber(int part_number) {
		switch (part_number) {
			case 0x1625:
			case 0x1626:
			case 0x1627:
			case 0x1628:
				return ScopeKind.TEK2465;

			case 0x3302:
			case 0x3303:
				return ScopeKind.TEK2465A;

			case 0x5370:
			case 0x5371:
				return ScopeKind.TEK2465B;

			case 0x5876:
			case 0x5877:
				return ScopeKind.TEK2465B_LATE;

			default:
				return ScopeKind.UNKNOWN;
		}
	}

	// Get the human readable name of a scope kind.
	public static String getScopeKindName(ScopeKind kind) {
		switch (kind) {
			case TEK2465:
				return "Tek2465";
			case TEK2465A:
				return "Tek2465A";
			case TEK2465B:
				return "Tek2465B";
			case TEK2465B_LATE:
				return "Tek2465B SN>B050000";
			default:
				return "Unknown";
		}
	}

	// Computes the checksum of the next `length` bytes in `str`.
	static int checksumRange(ByteProvider provider, int offset, int length) throws IOException {
		byte[] data = provider.readBytes(offset, length);
		int checksum = 0;
		for (int i = 0; i < data.length; ++i) {
			checksum <<= 1;
			checksum += (data[i] & 0xFF) + (checksum >> 16);
			checksum &= 0xFFFF;
		}

		return checksum;
	}

	// Returns true iff @str has a ROM header with a valid checksum.
	static boolean hasValidHeaderAt(ByteProvider provider, int offset) throws IOException {
		ROMHeader h = new ROMHeader(provider, offset);
		if (!h.isValid()) {
			return false;
		}

		if (checksumRange(provider, 0x0002, h.getByteSize() - 0x0002) != h.checksum) {
			return false;
		}

		if (h.tail_checksum != 0 &&
			checksumRange(provider, 0x0009, h.getByteSize() - 0x0009) != h.tail_checksum) {
			return false;
		}

		return true;
	}

	static int[] findValidRomHeaders(ByteProvider provider) throws IOException {
		return new int[0];
	}
}
