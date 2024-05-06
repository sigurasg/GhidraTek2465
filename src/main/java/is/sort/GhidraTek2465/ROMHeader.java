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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class ROMHeader {
	ROMHeader(ByteProvider provider, long index) throws IOException {
		// Read the ROM header.
		BinaryReader reader = new BinaryReader(provider, false);
		reader.setPointerIndex(index);

		checksum = reader.readNextUnsignedShort();
		part_number = reader.readNextUnsignedShort();
		version = reader.readNextUnsignedByte();
		version_compl = reader.readNextUnsignedByte();
		load_addr = reader.readNextUnsignedByte();
		tail_checksum = reader.readNextUnsignedShort();
		rom_end = reader.readNextUnsignedShort();
		next_rom = reader.readNextUnsignedShort();
		zero_effeff = reader.readNextUnsignedShort();
	}

	boolean IsValid() {
		if ((version ^ version_compl) != 0xFF) {
			return false;
		}

		if (zero_effeff != 0xFF) {
			return false;
		}

		// TODO(siggi): Check CRC, load addresses, etc.
		return true;
	}

	int getLoadAddress() {
		return load_addr << 8;
	}

	int getByteSize() {
		return rom_end + 1 - getLoadAddress();
	}

	// ROM header fields.
	// Checksum over the bytes after this field.
	final int checksum;
	// The part number encoded in hex, e.g. 0x3302 for 3302.
	final int part_number;
	// The firmware version.
	final int version;
	// Complement of the previous field.
	final int version_compl;
	// The upper byte of the ROM load address.
	final int load_addr;
	// Checksum over the bytes after this field.
	final int tail_checksum;
	// The last byte of this ROM.
	final int rom_end;
	// The address of the next ROM, if any.
	final int next_rom;
	// Fixed value - maybe a signature?
	final int zero_effeff;
}
