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
package is.sort.GhidraTek2465;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

import java.io.IOException;

public class ROMHeader {
	ROMHeader(ByteProvider provider, long index) throws IOException {
		// Read the ROM header.
		BinaryReader reader = new BinaryReader(provider, false);
		reader.setPointerIndex(index);

		checksum = reader.readNextUnsignedShort();
		part_number = reader.readNextUnsignedShort();
		version = reader.readNextUnsignedByte();
		version_compl = reader.readNextUnsignedByte();
		load_addr = reader.readNextUnsignedShort();
		unused1 = reader.readNextByte();
		rom_end = reader.readNextUnsignedShort();
		next_rom = reader.readNextUnsignedShort();
		zero = reader.readNextUnsignedByte();
		effeff = reader.readNextUnsignedByte();
	}

	boolean IsValid() {
		if ((version ^ version_compl) != 0xFF) {
			return false;
		}

		if (zero != 0 && effeff != 0xFF) {
			return false;
		}

		// TODO(siggi): Check CRC, load addresses, etc.
		return true;
	}

	// ROM header fields.
	int checksum;
	int part_number;
	int version;
	int version_compl;
	int load_addr;
	byte unused1;
	int rom_end;
	int next_rom;
	int zero;
	int effeff;
}
