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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class ROMHeader {
	ROMHeader(ByteProvider provider, long index) throws IOException {
		// Read the ROM header.
		BinaryReader reader = new BinaryReader(provider, false);
		reader.setPointerIndex(index);

		checksum = reader.readNextUnsignedShort();
		partNumber = reader.readNextUnsignedShort();
		version = reader.readNextUnsignedByte();
		versionCompl = reader.readNextUnsignedByte();
		loadAddr = reader.readNextUnsignedByte();
		tailChecksum = reader.readNextUnsignedShort();
		romEnd = reader.readNextUnsignedShort();
		nextRom = reader.readNextUnsignedShort();
		signature = reader.readNextUnsignedShort();
	}

	boolean isValid() {
		if ((version ^ versionCompl) != 0xFF || signature != 0x00FF) {
			return false;
		}
		return true;
	}

	int getLoadAddress() {
		return loadAddr << 8;
	}

	int getByteSize() {
		return romEnd + 1 - getLoadAddress();
	}

	// ROM header fields.
	// Checksum over the bytes after this field.
	final int checksum;
	// The part number encoded in hex, e.g. 0x3302 for 3302.
	final int partNumber;
	// The firmware version.
	final int version;
	// Complement of the previous field.
	final int versionCompl;
	// The upper byte of the ROM load address.
	final int loadAddr;
	// Checksum over the bytes after this field.
	final int tailChecksum;
	// The last byte of this ROM.
	final int romEnd;
	// The address of the next ROM, if any.
	final int nextRom;
	// Fixed value - maybe a signature?
	final int signature;
}
