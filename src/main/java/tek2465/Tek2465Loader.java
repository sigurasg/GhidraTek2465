/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package tek2465;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class Tek2465Loader extends AbstractProgramWrapperLoader {

	@Override
	public String getName() {

		// TODO(siggi): Figure this out. 
		// This name must match the name of the loader in the .opinion files.

		return "Tek2465 loader";
	}

	@Override
	public boolean supportsLoadIntoProgram(Program program) {
		return true;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (HasROMHeaderAndCRC(provider)) {
			LoadSpec spec = new LoadSpec(this, 0x8000, new LanguageCompilerSpecPair("MC6800:BE:16:default", "default"), true);
			loadSpecs.add(spec);
		}
		
		return loadSpecs;
	}

	class ROMHeader {
		ROMHeader(ByteProvider provider, long index) throws IOException {
			// Read the ROM header.
			BinaryReader reader = new BinaryReader(provider, false);
			reader.setPointerIndex(index);
			
			checksum = reader.readNextUnsignedShort();
			unknown = reader.readNextUnsignedShort();
			sig = reader.readNextUnsignedByte();
			sig_compl = reader.readNextUnsignedByte();
			load_addr = reader.readNextUnsignedShort();
			unused1 = reader.readNextByte();
			rom_end = reader.readNextUnsignedShort();
			next_rom = reader.readNextUnsignedShort();
			zero = reader.readNextUnsignedByte();
			effeff = reader.readNextUnsignedByte();
		}

		boolean IsValid() {
			if ((sig ^ sig_compl) != 0xFF)
				return false;
		
			if (zero != 0 && effeff != 0xFF)
				return false;
			
			// TODO(siggi): Check CRC, load addresses, etc.
			return true;
		}

		// ROM header fields.
		int checksum;
		int unknown;
		int sig;
		int sig_compl;
		int load_addr;
		byte unused1;
		int rom_end;
		int next_rom;
		int zero;
		int effeff;
	}
	
	private boolean HasROMHeaderAndCRC(ByteProvider provider) throws IOException {
		ROMHeader header = new ROMHeader(provider, 0);
		return header.IsValid();
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		var as = program.getAddressFactory().getDefaultAddressSpace();
		Memory memory = program.getMemory();
		
		program.getSymbolTable();

		try {
			// Only add the fixed blocks the first time invoked.
			if (memory.getBlock("RAM LO") == null) {
				// TODO(siggi): this is the 2465A, early 2465B version.
				// Create the RAM blocks.
				MemoryBlock blk = memory.createByteMappedBlock("RAM LO", as.getAddress(0x0000), as.getAddress(0x8000), 0x0800, false);
				blk.setPermissions(true, true, true);

				blk = memory.createUninitializedBlock("IO", as.getAddress(0x0800), 0x0800, false);
				blk.setPermissions(true, true, false);
				blk.setVolatile(true);
		
				blk = memory.createUninitializedBlock("Options", as.getAddress(0x1000), 0x7000, false);
				blk.setPermissions(true, true, true);

				blk = memory.createUninitializedBlock("RAM HI", as.getAddress(0x8000), 0x2000, false);
				blk.setPermissions(true, true, true);	
			}
			
			// Load the ROM pages.
			long length_remaining = provider.length();
			long page_index = 0;
			int page = 0;

			// Find the next page number.
			while (memory.getBlock("ROM_%d".formatted(page)) != null)
				++page;
			
			while (length_remaining > 0) {
				ROMHeader header = new ROMHeader(provider, page_index);
				if (!header.IsValid())
					throw new CancelledException("ROM header invalid.");
				
				// Find the load address for this page.
				int load_addr = header.load_addr & 0xFF00;
				Address addr = as.getAddress(header.load_addr & 0xFF00);
				if (load_addr != 0x8000) {
					// Check that there's a valid ROM header at the load address.
					header = new ROMHeader(provider, page_index + load_addr - 0x8000);
					if (!header.IsValid())
						throw new CancelledException("Load address ROM header invalid");
				}
				
				// Offset data and length with respect to the load address.				
				InputStream data = provider.getInputStream(page_index + load_addr - 0x8000);
				MemoryBlock blk = memory.createInitializedBlock("ROM_%d".formatted(page++), addr, data, 0x10000 - load_addr, monitor, true);
				blk.setPermissions(true, false, true);
				
				length_remaining -= 0x8000;
				page_index += 0x8000;
			}
		} catch (LockException | IllegalArgumentException | AddressOverflowException | AddressOutOfBoundsException | MemoryConflictException e) {
		    log.appendException(e);
		    throw new CancelledException("Loading failed: " + e.getMessage());
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		list.add(new Option("ScopeType", "2465a"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
