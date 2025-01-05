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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * This loader creates the address map for ROM images that satisfy the header signatures
 * and CRC checksums for the ROMs seen in the Tek2465 scopes.
 * For ROM versions it knows about, it also tags the banking functions, which in turn allows
 * the analyzer to propagate disassembly across ROM banks, and to create thunk functions
 * for the banking thunks.
 */
public class Tek2465Loader extends AbstractProgramLoader {
	private static final String OPTION_ADD_MEMORY_BLOCKS = "Add Memory Blocks";
	private static final String OPTION_ADD_TYPES = "Add Types";
	private static final String OPTION_SCOPE_KIND = "Scope Kind";

	@Override
	public String getName() {
		return "Tek2465";
	}

	@Override
	public boolean supportsLoadIntoProgram(Program program) {
		// Only support MC6800-language programs.
		if (!program.getLanguageID().equals(new LanguageID("MC6800:BE:16:default"))) {
			return false;
		}
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

		var headers = ROMUtils.findValidRomHeaders(provider);
		if (headers.length > 0) {
			LoadSpec spec = new LoadSpec(this, 0x8000,
				new LanguageCompilerSpecPair("MC6800:BE:16:default", "default"), true);
			loadSpecs.add(spec);
		}

		return loadSpecs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		ScopeKind scopeKind = ScopeKind.UNKNOWN;
		try {
			// Infer the scope kind from the first ROM header.
			var headers = ROMUtils.findValidRomHeaders(provider);
			ROMHeader header = new ROMHeader(provider, headers[0]);
			scopeKind = ROMUtils.scopeKindFromPartNumber(header.partNumber);
		}
		catch (IOException e) {
		}

		list.add(new ScopeKindOption(OPTION_SCOPE_KIND, scopeKind));
		if (!isLoadIntoProgram) {
			list.add(new Option(OPTION_ADD_TYPES, true));
			list.add(new Option(OPTION_ADD_MEMORY_BLOCKS, true));
		}

		return list;
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
		ScopeKind scopeKind = OptionUtils.getOption(OPTION_SCOPE_KIND, options, ScopeKind.UNKNOWN);
		boolean addTypes = OptionUtils.getOption(OPTION_ADD_TYPES, options, true);
		boolean addMemoryBlocks = OptionUtils.getOption(OPTION_ADD_MEMORY_BLOCKS, options, true);
		try {
			DataTypes dataTypes = null;
			if (addTypes) {
				int id = program.startTransaction("Add scope data types.");
				try {
					dataTypes = new DataTypes(scopeKind);
					dataTypes.addAll(program.getDataTypeManager());
				}
				finally {
					program.endTransaction(id, true);
				}
			}
			if (addMemoryBlocks) {
				int id = program.startTransaction("Add scope memory blocks.");
				try {
					addScopeMemoryBlocks(scopeKind, dataTypes, program);
				}
				finally {
					program.endTransaction(id, true);
				}
			}

			createDefaultMemoryBlocks(program, language, log);

			loadInto(provider, loadSpec, options, log, program, monitor);

			success = result.add(new Loaded<>(program, loadedName, projectFolderPath));
		}
		catch (LockException | MemoryConflictException | AddressOverflowException
				| CodeUnitInsertionException | InvalidInputException e) {
			log.appendException(e);
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

		var as = program.getAddressFactory().getDefaultAddressSpace();
		Memory memory = program.getMemory();

		// Back the memory blocks with FileBytes as there are cases where the full
		// contents of the binary are needed.
		FileBytes fileBytes = memory.createFileBytes(provider.getName(), 0, provider.length(),
			provider.getInputStream(0), monitor);

		try {
			int[] headerOffsets = ROMUtils.findValidRomHeaders(provider);
			// Derive the designator from the first (and possibly only) header.
			ROMHeader header = new ROMHeader(provider, headerOffsets[0]);
			String designator = ROMUtils.designatorFromPartNumber(header.partNumber);

			ROMUtils.FunctionInfo[] knownFunctions =
				ROMUtils.getKnownFunctions(header.partNumber, header.version);

			for (int bank = 0; bank < headerOffsets.length; ++bank) {
				int offset = headerOffsets[bank];
				header = new ROMHeader(provider, offset);

				// Find the load address for this page.
				int loadAddr = header.getLoadAddress();
				Address addr = as.getAddress(loadAddr);

				String name;
				if (headerOffsets.length == 1) {
					name = designator;
				}
				else {
					name = "%s-%d".formatted(designator, bank);
				}
				// Create the ROM memory block.
				MemoryBlock blk = memory.createInitializedBlock(name, addr, fileBytes, offset,
					header.getByteSize(), ROMUtils.isOverlay(header));
				initializeNewBlock(program, knownFunctions, bank, blk);
			}

			if (ROMUtils.scopeKindFromPartNumber(header.partNumber) == ScopeKind.TEK2465B) {
				// There is a special case with these scopes where one bank is stitched
				// together from otherwise occluded segments of two ROMs.
				List<FileBytes> allFileBytes = memory.getAllFileBytes();
				if (allFileBytes.size() == 2) {
					maybeCreateStitchedMemoryBlock(program, knownFunctions, allFileBytes, log,
						monitor);
				}
			}
		}
		catch (Exception e) {
			log.appendException(e);
			throw new CancelledException("Loading failed: " + e.getMessage());
		}
	}

	private void initializeNewBlock(Program program, ROMUtils.FunctionInfo[] knownFunctions,
			int bank,
			MemoryBlock blk) throws CodeUnitInsertionException, InvalidInputException,
			AddressOutOfBoundsException, MemoryAccessException {
		blk.setPermissions(true, false, true);

		createData(program, blk.getStart(), DataTypes.ROM_HEADER, -1,
			ClearDataMode.CLEAR_ALL_CONFLICT_DATA);

		AddressSpace space = blk.getAddressRange().getAddressSpace();
		for (var knownFunction : knownFunctions) {
			if (knownFunction.bank == bank) {
				markAsFunction(program, knownFunction.name,
					space.getAddress(knownFunction.location));
			}
		}
		maybeAddProcessorVectors(program, space, blk);
	}

	private MemoryBlock maybeCreateStitchedMemoryBlock(Program program,
			ROMUtils.FunctionInfo[] knownFunctions,
			List<FileBytes> allFileBytes, MessageLog log, TaskMonitor monitor)
			throws CodeUnitInsertionException, Exception {
		// Start by verifying that we have one each a 160-5370-X and 160-5371-X.
		FileBytes first = allFileBytes.get(0);
		FileBytes second = allFileBytes.get(1);

		// See whether the part numbers are possibly switched around.
		ROMHeader header1 = getHeaderForFileBytes(first);
		if (header1.partNumber == 0x5371) {
			// Switch the file bytes around.
			first = allFileBytes.get(1);
			second = allFileBytes.get(0);
		}

		// Redo header snoop in case of switching above.
		header1 = getHeaderForFileBytes(first);
		ROMHeader header2 = getHeaderForFileBytes(second);
		if (header1.partNumber != 0x5370 || header2.partNumber != 0x5371) {
			// We don't have the right part numbers. Bail.
			log.appendMsg("Can't create a stitch block with part numbers %04X and %04X"
					.formatted(header1.partNumber, header2.partNumber));
			return null;
		}

		// Construct the ROM image in memory to pre-flight the operation.
		byte[] bytes = new byte[0x6000];
		first.getOriginalBytes(0x8000, bytes, 0, 0x2000);
		second.getOriginalBytes(0x0000, bytes, 0x2000, 0x2000);
		second.getOriginalBytes(0x8000, bytes, 0x4000, 0x2000);
		ByteArrayProvider provider = new ByteArrayProvider(bytes);

		// Make sure the stitched ROM image is valid.
		if (!ROMUtils.hasValidHeaderAt(provider, 0)) {
			// We don't have a valid ROM image. Bail.
			log.appendMsg("Can't create a stitch block, malformed ROM image.");
			return null;
		}

		// Validate that the part number and load address are what we expect.
		ROMHeader header = new ROMHeader(provider, 0);
		if (header.partNumber != 0x5371 || header.getLoadAddress() != 0xA000) {
			log.appendMsg("Can't create a stitch block, unexpected part number or load address.");
			return null;
		}

		// OK we have a valid stitched ROM image. Now create the stitched up memory block by
		// joining three smaller blocks.
		AddressSpace as = program.getAddressFactory().getDefaultAddressSpace();
		Memory memory = program.getMemory();
		final long chunkSize = 0x2000;

		// The overlay address space name is derived from the block that engenders it,
		// and the joined-up block will take the name of the first one in sequence.
		// Since the ROM header identifies this as part number 5371, we name it like
		// an additional bank on U2260.
		MemoryBlock one =
			memory.createInitializedBlock("U2260-2", as.getAddress(0xA000), first, 0x8000,
				chunkSize, true);

		// Create the blocks back to back from the same overlay address space by stringing
		// their addresses back to back.
		MemoryBlock two =
			memory.createInitializedBlock("U2260@0000", one.getStart().add(chunkSize), second, 0x0,
				chunkSize, false);
		MemoryBlock three =
			memory.createInitializedBlock("U2260@8000", two.getStart().add(chunkSize), second,
				0x8000, chunkSize, false);
		MemoryBlock stitched = memory.join(one, two);
		stitched = memory.join(stitched, three);

		initializeNewBlock(program, knownFunctions, 2, stitched);

		return stitched;
	}

	private ROMHeader getHeaderForFileBytes(FileBytes fileBytes) throws IOException {
		final int expectedSize = 0x10000;
		// Make sure the files are the correct size.
		if (fileBytes.getSize() != expectedSize) {
			return null;
		}
		byte[] bytes = new byte[expectedSize];
		fileBytes.getOriginalBytes(0, bytes);
		ByteArrayProvider provider = new ByteArrayProvider(bytes);
		int[] headerOffsets = ROMUtils.findValidRomHeaders(provider);
		if (headerOffsets.length < 1) {
			return null;
		}
		ROMHeader header = new ROMHeader(provider, headerOffsets[0]);
		return header;
	}

	private void addScopeMemoryBlocks(ScopeKind scopeKind, DataTypes dataTypes, Program program)
			throws LockException, MemoryConflictException, AddressOverflowException,
			CodeUnitInsertionException, InvalidInputException {
		Memory memory = program.getMemory();
		AddressSpace as = program.getAddressFactory().getDefaultAddressSpace();

		// Create and optionally type the IO space.
		MemoryBlock blk =
			memory.createUninitializedBlock("IO", as.getAddress(0x0800), 0x0800, false);
		blk.setPermissions(true, true, false);
		blk.setVolatile(true);
		createData(program, blk.getStart(), dataTypes != null ? dataTypes.ioRegion : null, -1,
			ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		program.getSymbolTable().createLabel(blk.getStart(), "io", SourceType.IMPORTED);

		switch (scopeKind) {
			case TEK2465:
				blk =
					memory.createUninitializedBlock("RAM", as.getAddress(0x0000), 0x0800, false);
				blk.setPermissions(true, true, true);
				break;

			case TEK2465A:
			case TEK2465B:
			case TEK2465B_LATE:
				// Create the RAM blocks.
				blk = memory.createByteMappedBlock("RAM LO", as.getAddress(0x0000),
					as.getAddress(0x8000), 0x0800, false);
				blk.setPermissions(true, true, true);

				blk =
					memory.createUninitializedBlock("RAM HI", as.getAddress(0x8000), 0x2000, false);
				blk.setPermissions(true, true, true);
				break;

			case UNKNOWN:
				throw new InvalidInputException("Unknown scope type.");
			}

		// Create the options space.
		blk = null;
		switch (scopeKind) {
			case TEK2465:
			case TEK2465A:
			case TEK2465B:
				blk = memory.createUninitializedBlock("Options", as.getAddress(0x1000), 0x7000,
					false);
				break;
			case TEK2465B_LATE:
				blk = memory.createUninitializedBlock("Options", as.getAddress(0x2000), 0x6000,
					false);
				break;

			default:
				break;
		}
		if (blk != null) {
			blk.setPermissions(true, true, true);
		}
	}

	private void maybeAddProcessorVectors(Program program, AddressSpace space, MemoryBlock blk)
			throws CodeUnitInsertionException, InvalidInputException, AddressOutOfBoundsException,
			MemoryAccessException {
		addProcessorVector(program, space, blk, 0xFFFE, "RST");
		addProcessorVector(program, space, blk, 0xFFFC, "NMI");
		addProcessorVector(program, space, blk, 0xFFFA, "SWI");
		addProcessorVector(program, space, blk, 0xFFF8, "IRQ");
	}

	private void addProcessorVector(Program program, AddressSpace space, MemoryBlock blk, long loc,
			String name) throws CodeUnitInsertionException, InvalidInputException,
			AddressOutOfBoundsException, MemoryAccessException {
		Address addr = space.getAddress(loc);
		if (blk.contains(addr)) {
			createData(program, addr, DataTypes.PTR, -1, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			program.getSymbolTable().createLabel(addr, name + "_VECTOR", SourceType.IMPORTED);
			markAsFunction(program, name + "_" + blk.getName(),
				space.getAddress(program.getMemory().getShort(addr)));
		}

	}
}
