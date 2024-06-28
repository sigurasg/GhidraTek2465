// Finds, decodes and marks on-screen-display strings in Tektronix 2465 ROMs.
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

import java.util.HashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.NotFoundException;

public class FindOSDStrings extends GhidraScript {
	public FindOSDStrings() {
	}

	@Override
	protected void run() throws Exception {
		stringType = getDataTypes("string")[0];

		// Get the LO RAM memory block. This is named either
		// "RAM" on the 2465 or "RAM LO" on all others.
		MemoryBlock ram = getMemoryBlock("RAM LO");
		if (ram == null) {
			ram = getMemoryBlock("RAM");
		}
		if (ram == null) {
			throw new NotFoundException("RAM block not found.");
		}

		Set<Address> foundStrings = new HashSet<Address>();
		Address varAddress = ram.getStart().add(osdStringPointerOffset);
		for (Reference ref: getReferencesTo(varAddress)) {
			// Look for a sequence of LDX/STX instructions.
			Instruction stx = getInstructionAt(ref.getFromAddress());
			if (!stx.getMnemonicString().equals("STX")) {
				continue;
			}
			Instruction ldx = stx.getPrevious();
			if (!ldx.getMnemonicString().equals("LDX")) {
				continue;
			}

			// We have an LDX/STX sequence, make sure it's an immeediate 16
			// bit load.
			Object[] opObjects = ldx.getOpObjects(0);
			if (opObjects.length != 1 ||  !(opObjects[0] instanceof Scalar)) {
				continue;
			}
			// TODO(siggi): Check ldx.getOperandType(0)?

			AddressSpace space = ldx.getAddress().getAddressSpace();
			// Get the start of the string in the instruction's address space.
			Address stringStart = space.getAddress(
					((Scalar)opObjects[0]).getUnsignedValue());
			foundStrings.add(stringStart);

			byte[] osdBytes = OSDStrings.readOSDStringBytes(ldx.getMemory(), stringStart);
			if (osdBytes == null) {
				currentProgram.getBookmarkManager().
					setBookmark(stringStart, "Error", "OSD_STRING", "Unable to read OSD string.");
				continue;
			}

			String osdString = OSDStrings.decodeOSDString(osdBytes);
			if (osdString == null) {
				currentProgram.getBookmarkManager().
					setBookmark(stringStart, "Error", "OSD_STRING", "Unable to decode OSD string.");
				continue;
			}

			// Create a bookmark for the string.
			createBookmark(stringStart, "OSD_STRING", osdString);

			// Create a reference from the first operand of the LDX instruction
			// to the string. Start by removing any pre-existing reference.
			ldx.removeOperandReference(0, stringStart);
			createMemoryReference(ldx,  0,  stringStart, RefType.DATA);

			// Find or create a data block for the string.
			Data data = findOrCreateOSDStringData(stringStart, osdBytes.length + 1);
			if (data == null) {
				currentProgram.getBookmarkManager().
					setBookmark(stringStart, "Error", "OSD_STRING", "Unable to find or create data.");
				continue;
			}

			// Add the string as a comment on the data block.
			data.setComment(data.EOL_COMMENT, osdString);
		}
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

	private final long osdStringPointerOffset = 0x7A;
	private DataType stringType;
}
