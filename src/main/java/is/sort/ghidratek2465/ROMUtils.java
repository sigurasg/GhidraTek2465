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
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import com.opencsv.CSVReader;

import ghidra.app.util.bin.ByteProvider;

public class ROMUtils {
	// Get the human readable name of @p kind.
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

	// Find the scope kind from @p partNumber.
	public static ScopeKind scopeKindFromPartNumber(int partNumber) {
		switch (partNumber) {
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

	// Find the component designator from the @p partNumber.
	public static String designatorFromPartNumber(int partNumber) {
		switch (partNumber) {
			case 0x1625:
				return "U2178";
			case 0x1626:
				return "U2378";
			case 0x1627:
				return "U2362";
			case 0x1628:
				return "U2162";

			case 0x3302:
				return "U2160";
			case 0x3303:
				return "U2260";

			case 0x5370:
				return "U2160";
			case 0x5371:
				return "U2260";

			case 0x5876:
				return "U2160";
			case 0x5877:
				return "U2360";

			default:
				return "UNKNOWN";
		}
	}

	public static boolean isOverlay(ROMHeader header) {
		switch (scopeKindFromPartNumber(header.partNumber)) {
			case TEK2465:
				return false;

			case TEK2465A:
			case TEK2465B:
				return true;

			case TEK2465B_LATE:
				return header.getLoadAddress() == 0xC000;

			default:
				return true;
		}
	}

	/*
	 * Computes the checksum of the next @p length bytes from @p offset in @p provider.
	 */
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

	// Returns true iff @provider has a ROM header with a valid checksum at @p offset.
	static boolean hasValidHeaderAt(ByteProvider provider, int offset) throws IOException {
		ROMHeader h = new ROMHeader(provider, offset);
		if (!h.isValid()) {
			return false;
		}

		// Apparently there are cases where the primary checksum is invalid, but then
		// the tail checksum is fine, so we succeed if either checksum is good.
		// This specifically refers to the TekWiki image of 160-5370-04, but then it
		// also embeds the wrong part number so YMMV.
		if (checksumRange(provider, offset + 0x0002, h.getByteSize() - 0x0002) == h.checksum) {
			return true;
		}

		if (h.tailChecksum != 0 &&
			checksumRange(provider, offset + 0x0009,
				h.getByteSize() - 0x0009) == h.tailChecksum) {
			return true;
		}

		return false;
	}

	/*
	 * Locates valid ROM headers in @p provider and returns their offsets.
	 */
	static int[] findValidRomHeaders(ByteProvider provider) throws IOException {
		List<Integer> result = new ArrayList<Integer>();

		// Probe every 4k. Technically this is not correct, as it might turn up
		// overlapping ROM images. Should work well enough for our purposes,
		// though.
		for (int offset = 0; offset < provider.length(); offset += 0x1000) {
			if (hasValidHeaderAt(provider, offset)) {
				result.add(offset);
			}
		}

		return result.stream().mapToInt(Integer::intValue).toArray();
	}

	public static class FunctionInfo {
		public FunctionInfo(int bank, int location, String name) {
			this.bank = bank;
			this.location = location;
			this.name = name;
		}

		public final int bank;
		public final int location;
		public final String name;
	}

	/*
	 * Returns the set of known functions for a given ROM version.
	 */
	static public FunctionInfo[] getKnownFunctions(int partNumber, int version)
			throws IOException {
		return readKnownFunctions(
			"/knownFunctions/160-%04x-%02d.csv".formatted(partNumber, version));
	}

	static private FunctionInfo[] readKnownFunctions(String resourceName) throws IOException {
		ArrayList<FunctionInfo> functions = new ArrayList<FunctionInfo>();
		var stream = ROMUtils.class.getResourceAsStream(resourceName);
		if (stream != null) {
			var reader = new InputStreamReader(stream);
			CSVReader csvReader = new CSVReader(reader);
			try {
				String[] line;
				// Skip the header line.
				line = csvReader.readNext();
				while ((line = csvReader.readNext()) != null) {
					int bank = Integer.decode(line[0]);
					int location = Integer.decode(line[1]);
					String name = line[2];

					functions.add(new FunctionInfo(bank, location, name));
				}
			}
			finally {
				csvReader.close();
			}
		}
		FunctionInfo[] ret = new FunctionInfo[functions.size()];
		return functions.toArray(ret);
	}
}
