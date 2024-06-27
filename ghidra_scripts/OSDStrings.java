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
import static java.util.Map.entry;

import java.io.ByteArrayOutputStream;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class OSDStrings {

	static public String decodeOSDString(byte[] osdBytes) {
		String ret = "";
		for (int i = 0; i < osdBytes.length; ++i) {
			int key = osdBytes[i] & 0xFF;
			if (alphabet.containsKey(key)) {
				ret = ret + alphabet.get(key);
				continue;
			}
			++i;
			if (i == osdBytes.length) {
				return null;
			}

			key = (key << 8) | osdBytes[i] & 0xFF;
			if (!alphabet.containsKey(key)) {
				return null;
			}

			ret = ret + alphabet.get(key);
		}

		return ret;
	}

	static public byte[] readOSDStringBytes(Memory memory, Address stringStart) {
		// Try to read a 0xFF-terminated string.
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		for (int i =0 ; i < 257; i ++) {
			byte chr;
			try {
				chr = memory.getByte(stringStart.add(i));
			} catch (MemoryAccessException e) {
				return null;
			}
			if (chr == EOS) {
				return bytes.toByteArray();
			}
			bytes.write(chr);
		}

		return null;
	}

	static private Map<Integer, String> getOSDAlphabet() {
		Map<Integer, String> ret = Map.ofEntries(
				entry(0x00, "1"),
				entry(0x0201, "/0"),
				entry(0x04, "4"),
				entry(0x0605, "/1"),
				entry(0x08, "7"),
				entry(0x0A09, "/2"),
				entry(0x0C, "t"),
				entry(0x0E0D, "/3"),
				entry(0x0F, "k"),
				entry(0x10, "Z"),
				entry(0x1211, "/4"),
				entry(0x13, "..."),
				entry(0x14, "n"),
				entry(0x1615, "/5"),
				entry(0x18, "mu"),
				entry(0x1A19, "/6"),
				entry(0x1C, "/"),
				entry(0x1E1D, "/7"),
				entry(0x1F, ".."),
				entry(0x20, "delta"),
				entry(0x2221, "/8"),
				entry(0x24, "up"),
				entry(0x2625, "/9"),
				entry(0x28, "0"),
				entry(0x2A, "2"),
				entry(0x2B, "down"),
				entry(0x2C, "3"),
				entry(0x2D, "<"),
				entry(0x2E, "5"),
				entry(0x30, "6"),
				entry(0x31, ">"),
				entry(0x32, "8"),
				entry(0x34, "9"),
				entry(0x35, "~v"),
				entry(0x36, "1."),
				entry(0x3837, "/0."),
				entry(0x3A, "4."),
				entry(0x3C3B, "/1."),
				entry(0x3E, "7."),
				entry(0x403F, "/2."),
				entry(0x42, "%"),
				entry(0x4443, "/3."),
				entry(0x46, "s"),
				entry(0x4847, "/4."),
				entry(0x4A, "z"),
				entry(0x4C4B, "/5."),
				entry(0x4E, ".."),
				entry(0x504F, "/6."),
				entry(0x52, "-"),
				entry(0x5453, "/7."),
				entry(0x56, "~"),
				entry(0x5857, "/8."),
				entry(0x5A, ","),
				entry(0x5C5B, "/9."),
				entry(0x5E, "0."),
				entry(0x60, "2."),
				entry(0x62, "3."),
				entry(0x64, "5."),
				entry(0x66, "6."),
				entry(0x68, "8."),
				entry(0x6A, "9."),
				entry(0x6C, "U"),
				entry(0x6E6D, "/R"),
				entry(0x70, "V"),
				entry(0x7271, "/S"),
				entry(0x74, "X"),
				entry(0x7675, "/T"),
				entry(0x78, "m/n/l"),
				entry(0x7B7A, "/V"),
				entry(0x7C, "Y"),
				entry(0x7D, "deg"),
				entry(0x7E, "h/o"),
				entry(0x8180, "/X"),
				entry(0x82, "0|0"),
				entry(0x84, "0|1"),
				entry(0x86, "1|0"),
				entry(0x88, "A"),
				entry(0x8A, "B"),
				entry(0x8C, "D"),
				entry(0x8E, "H"),
				entry(0x90, "M"),
				entry(0x92, "N"),
				entry(0x94, "R"),
				entry(0x96, "W"),
				entry(0x98, "I"),
				entry(0x9A99, "/F"),
				entry(0x9C, "J"),
				entry(0x9E9D, "/Ohm"),
				entry(0xA0, "K"),
				entry(0xA2A1, "/H"),
				entry(0xA5Ad, "/d"),
				entry(0xA6, "="),
				entry(0xA7, "+"),
				entry(0xA8, "L"),
				entry(0xA9, "Ohm"),
				entry(0xAA, "GND"),
				entry(0xAC, "O"),
				entry(0xAEAD, "/L"),
				entry(0xB0, "P"),
				entry(0xB1, ":"),
				entry(0xB2, "1|1"),
				entry(0xB4, "Q"),
				entry(0xB5, "?"),
				entry(0xB6, "0|X"),
				entry(0xB8, "S"),
				entry(0xBAB9, "/O"),
				entry(0xBC, "T"),
				entry(0xBD, "d"),
				entry(0xBE, "X|0"),
				entry(0xC0, "."),
				entry(0xC2C1, "/A"),
				entry(0xC4, "C"),
				entry(0xC6C5, "/B"),
				entry(0xC8, "E"),
				entry(0xCAC9, "/C"),
				entry(0xCC, "F"),
				entry(0xCECD, "/D"),
				entry(0xD0, "G"),
				entry(0xD2D1, "/E"),
				entry(0xD4, "."),
				entry(0xD6D5, "/n"),
				entry(0xD8D7, "/mu"),
				entry(0xDAD9, "/k"),
				entry(0xDCDB, "/m"),
				entry(0xDFDE, "/+"),
				entry(0xE0, "-"),
				entry(0xE2E1, "/DLY"),
				entry(0xE4, "H/L/D"),
				entry(0xE6, "1|X"),
				entry(0xE8, "X|1"),
				entry(0xEA, "BWL"),
				entry(0xEC, "1/"),
				entry(0xED, "-"),
				entry(0xEE, "p"),
				entry(0xF0, "...."),
				entry(0xF1, "--"),
				entry(0xF3F2, "/S"),
				entry(0xF5F4, "/z"),
				entry(0xF6, "..."),
				entry(0xF7, "|"),
				entry(0xF8, "dt"),
				entry(0xFA, "-"),
				entry(0xFB, "...."),
				entry(0xFC, "X|X"),
				entry(0xFE, "m"));

		return ret;
	}

	private final static byte EOS = (byte)0xFF;
	private final static Map<Integer,String> alphabet = getOSDAlphabet();
}
