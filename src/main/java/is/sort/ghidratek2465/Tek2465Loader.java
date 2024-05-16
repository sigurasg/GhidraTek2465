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

import static ghidra.program.model.data.DataUtilities.createData;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class Tek2465Loader extends AbstractProgramLoader {
	@Override
	public String getName() {
		return "Tek2465";
	}

	@Override
	public boolean supportsLoadIntoProgram() {
		return true;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 0;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (HasROMHeaderAndCRC(provider)) {
			LoadSpec spec = new LoadSpec(this, 0x8000,
				new LanguageCompilerSpecPair("MC6800:BE:16:default", "default"), true);
			loadSpecs.add(spec);
		}

		return loadSpecs;
	}

	private boolean HasROMHeaderAndCRC(ByteProvider provider) throws IOException {
		ROMHeader header = new ROMHeader(provider, 0);
		int offset = 0;
		if (!header.isValid()) {
			// Secondary ROMs may not have a header at the start.
			header = new ROMHeader(provider, 0x2000);
			offset = 0x2000;
		}
		if (!header.isValid()) {
			return false;
		}
		int checksum = ROMUtils.checksumRange(provider, offset + 0x0002, header.getByteSize() - 2);

		if (header.checksum != checksum) {
			return false;
		}

		return true;
	}

	@Override
	protected List<Loaded<Program>> loadProgram(ByteProvider provider, String loadedName,
			Project project, String projectFolderPath, LoadSpec loadSpec, List<Option> options,
			MessageLog log, Object consumer, TaskMonitor monitor)
			throws IOException, CancelledException {
		var result = new ArrayList<Loaded<Program>>();
		var pair = loadSpec.getLanguageCompilerSpec();
		var language = getLanguageService().getLanguage(pair.languageID);
		var compiler = language.getCompilerSpecByID(pair.compilerSpecID);

		var baseAddress = language.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		var program = createProgram(provider, loadedName, baseAddress, getName(), language,
			compiler, consumer);
		var success = false;
		try {
			loadInto(provider, loadSpec, options, log, program, monitor);
			createDefaultMemoryBlocks(program, language, log);

			success = result.add(new Loaded<>(program, loadedName, projectFolderPath));
		}
		finally {
			if (!success) {
				program.release(consumer);
			}
		}
		return result;
	}

	@Override
	protected void loadProgramInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			MessageLog log, Program program, TaskMonitor monitor)
			throws IOException, CancelledException {
		DataTypes.addAll(program.getDataTypeManager());

		var as = program.getAddressFactory().getDefaultAddressSpace();
		Memory memory = program.getMemory();

		try {
			// Only add the fixed blocks the first time invoked.
			if (memory.getBlock("RAM LO") == null) {
				// TODO(siggi): this is the 2465A, early 2465B version.
				// Create the RAM blocks.
				MemoryBlock blk = memory.createByteMappedBlock("RAM LO", as.getAddress(0x0000),
					as.getAddress(0x8000), 0x0800, false);
				blk.setPermissions(true, true, true);

				blk = memory.createUninitializedBlock("IO", as.getAddress(0x0800), 0x0800, false);
				blk.setPermissions(true, true, false);
				blk.setVolatile(true);
				createData(program, blk.getStart(), DataTypes.IO_REGION, -1,
					ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
				program.getSymbolTable().createLabel(blk.getStart(), "io", SourceType.ANALYSIS);

				blk = memory.createUninitializedBlock("Options", as.getAddress(0x1000), 0x7000,
					false);
				blk.setPermissions(true, true, true);

				blk =
					memory.createUninitializedBlock("RAM HI", as.getAddress(0x8000), 0x2000, false);
				blk.setPermissions(true, true, true);
			}

			// Load the ROM pages.
			long length_remaining = provider.length();
			long page_index = 0;
			int page = 0;

			// Find the next page number.
			while (memory.getBlock("ROM_%d".formatted(page)) != null) {
				++page;
			}

			while (length_remaining > 0) {
				ROMHeader header = new ROMHeader(provider, page_index);
				if (!header.isValid()) {
					// Check for a header at the supposed load address.
					header = new ROMHeader(provider, page_index + 0x2000);
				}
				if (!header.isValid()) {
					throw new CancelledException("ROM header invalid.");
				}

				// Find the load address for this page.
				int load_addr = header.getLoadAddress();
				Address addr = as.getAddress(load_addr);
				if (load_addr != 0x8000) {
					// Check that there's a valid ROM header at the load address.
					header = new ROMHeader(provider, page_index + load_addr - 0x8000);
					if (!header.isValid()) {
						throw new CancelledException("Load address ROM header invalid");
					}
				}

				// Offset data and length with respect to the load address.
				InputStream data = provider.getInputStream(page_index + load_addr - 0x8000);
				MemoryBlock blk = memory.createInitializedBlock("ROM_%d".formatted(page++), addr,
					data, 0x10000 - load_addr, monitor, true);
				blk.setPermissions(true, false, true);

				createData(program, blk.getStart(), DataTypes.ROM_HEADER, -1,
					ClearDataMode.CLEAR_ALL_CONFLICT_DATA);

				length_remaining -= 0x8000;
				page_index += 0x8000;

				ProcessVector(program, blk, 0xFFFE, "RST");
				ProcessVector(program, blk, 0xFFFC, "NMI");
				ProcessVector(program, blk, 0xFFFA, "SWI");
				ProcessVector(program, blk, 0xFFF8, "IRQ");
			}
		}
		catch (Exception e) {
			log.appendException(e);
			throw new CancelledException("Loading failed: " + e.getMessage());
		}
	}

	private void ProcessVector(Program program, MemoryBlock blk, int address, String name)
			throws Exception {
		AddressSpace ovl = blk.getAddressRange().getAddressSpace();
		Address addr = ovl.getAddress(address);
		createData(program, addr, DataTypes.ptr, -1, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		program.getSymbolTable().createLabel(addr, name + "_VECTOR", SourceType.ANALYSIS);
		markAsFunction(program, name + "_" + blk.getName(),
			ovl.getAddress(program.getMemory().getShort(addr)));
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
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
