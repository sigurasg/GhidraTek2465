// Decodes and marks an on-screen-display string at the current
// selection in Tektronix 2465 ROMs.
//
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
//@author Sigurður Ásgeirsson
//@category Tek2465
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.util.CodeUnitInsertionException;

public class DecodeOSDString extends GhidraScript {
	public DecodeOSDString() {
	}

	@Override
	protected void run() throws Exception {
		stringType = getDataTypes("string")[0];
		Address stringStart = currentAddress;
		byte[] osdBytes = OSDStrings.readOSDStringBytes(currentProgram.getMemory(), stringStart);
		if (osdBytes == null) {
			println("Unable to read OSD string at %s.".formatted(stringStart));
			return;
		}

		String osdString = OSDStrings.decodeOSDString(osdBytes);
		if (osdString == null) {
			println("Unable to decode OSD string at %s.".formatted(stringStart));
			return;
		}

		// Create a bookmark for the string.
		createBookmark(stringStart, "OSD_STRING", osdString);

		// Find or create a data block for the string.
		Data data = findOrCreateOSDStringData(stringStart, osdBytes.length + 1);
		if (data == null) {
			println("Unable to find or create data at %s.".formatted(stringStart));
			return;
		}

		// Add the string as a comment on the data block.
		data.setComment(data.EOL_COMMENT, osdString);
	}

	private Data findOrCreateOSDStringData(Address stringStart, int length) {
		Listing listing = currentProgram.getListing();
		Data data = listing.getDataAt(stringStart);
		if (data != null && data.getLength() == length) {
			return data;
		}

		try {
			data = listing.createData(stringStart, stringType, length);
		} catch (CodeUnitInsertionException e) {
		}

		return data;
	}

	private DataType stringType;
}
