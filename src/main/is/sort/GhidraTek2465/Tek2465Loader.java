// Copyright 2022-2024 Sigurdur Asgeirsson <siggi@sort.is>
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

import static ghidra.program.model.data.DataUtilities.createData;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Pointer16DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
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
public class Tek2465Loader extends AbstractProgramWrapperLoader {
	private class ROMHeader {
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

	private static final CategoryPath PATH = new CategoryPath(CategoryPath.ROOT, "2465a");
	public static final Pointer16DataType ptr = Pointer16DataType.dataType;
	public static final ByteDataType u8 = ByteDataType.dataType;
	public static final WordDataType u16 = WordDataType.dataType;
	public static final Structure ROM_HEADER;
	public static final Structure IO_REGION;
	public static final Enum PORT_1;

	static {
		ROM_HEADER = new StructureDataType(PATH, "ROMHeader", 0);
		ROM_HEADER.add(u16, "checksum", null);
		ROM_HEADER.add(u16, "part_number", null);
		ROM_HEADER.add(u8, "version", null);
		ROM_HEADER.add(u8, "version_compl", null);
		ROM_HEADER.add(u16, "load_addr", null);
		ROM_HEADER.add(u8, "unused", null);
		ROM_HEADER.add(u16, "rom_end", null);
		ROM_HEADER.add(u16, "next_rom", null);
		ROM_HEADER.add(u8, "zero", null);
		ROM_HEADER.add(u8, "effeff", null);

		IO_REGION = new StructureDataType(PATH, "io", 0);
		IO_REGION.add(array(u8, 64), "dmux2_off", null);
		IO_REGION.add(array(u8, 63), "dac_msb", null);
		IO_REGION.add(u16, "dac_full", null);
		IO_REGION.add(array(u8, 63), "dac_lsb", null);
		// Create a bit field for port 1.
		StructureDataType port_1 = new StructureDataType("p1", 0);
		port_1.setPackingEnabled(true);
		try {
			port_1.addBitField(u8, 3, "mux_sel", null);
			port_1.addBitField(u8, 1, "rom_select", null);
			port_1.addBitField(u8, 1, "page_select", null);
			port_1.addBitField(u8, 1, "pwr_down", null);
		} catch (InvalidDataTypeException e) {
			e.printStackTrace();
		}

		IO_REGION.add(array(port_1, 64), "port_1_clk", null);
		IO_REGION.add(array(u8, 64), "ros_1_clk", null);
		IO_REGION.add(array(u8, 64), "ros_2_clk", null);
		IO_REGION.add(array(u8, 64), "port_2_clk", null);

		Structure fine = new StructureDataType("f", 0);
		fine.add(u8, "dmux2_on", null);
		fine.add(u8, "dmux0_off", null);
		fine.add(u8, "dmux0_on", null);
		fine.add(u8, "port_3_in", null);
		fine.add(u8, "dmux1_off", null);
		fine.add(u8, "dmux1_on", null);
		fine.add(u8, "led_clk", null);
		fine.add(u8, "disp_seq_clk", null);
		fine.add(u8, "atn_clk", null);
		fine.add(u8, "ch_2_pa_clk", null);
		fine.add(u8, "ch_1_pa_clk", null);
		fine.add(u8, "b_swp_clk", null);
		fine.add(u8, "a_swp_clk", null);
		fine.add(u8, "b_trig_clk", null);
		fine.add(u8, "a_trig_clk", null);
		fine.add(u8, "trig_stat_strb", null);
		IO_REGION.add(array(fine, 4), "f", null);

		PORT_1 = new EnumDataType(PATH, "Port1", 1);
		PORT_1.add("MUX_MASK", 0x7);
		PORT_1.add("ROM_SELECT", 0x8);
		PORT_1.add("PAGE_SELECT", 0x10);
		PORT_1.add("PWR_DOWN", 0x20);
	}

    static Array array(DataType d, int size) {
        return new ArrayDataType(d, size, -1);
    }

	@Override
	public String getName() {
		// TODO(siggi): Analyze the ROMs and discern between 2465/A/B ROMs, or
		//    else take an argument.
		return "Tek2465A ROM";
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

	private boolean HasROMHeaderAndCRC(ByteProvider provider) throws IOException {
		ROMHeader header = new ROMHeader(provider, 0);
		if (header.IsValid()) {
			return true;
		}

		// Secondary ROMs may not have a header at the start.
		header = new ROMHeader(provider, 0x2000);
		return header.IsValid();
	}

	private void addDataTypes(DataTypeManager manager) {
        var c = manager.createCategory(PATH);
        c.addDataType(ROM_HEADER, null);
        c.addDataType(IO_REGION, null);
        c.addDataType(PORT_1, null);
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		addDataTypes(program.getDataTypeManager());

		var as = program.getAddressFactory().getDefaultAddressSpace();
		Memory memory = program.getMemory();

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
				createData(program,  blk.getStart(), array(IO_REGION, 4), -1, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
				program.getSymbolTable().createLabel(blk.getStart(), "io", SourceType.ANALYSIS);

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
			while (memory.getBlock("ROM_%d".formatted(page)) != null) {
				++page;
			}

			while (length_remaining > 0) {
				ROMHeader header = new ROMHeader(provider, page_index);
				if (!header.IsValid()) {
					// Check for a header at the supposed load address.
					header = new ROMHeader(provider, page_index + 0x2000);
				}
				if (!header.IsValid()) {
					throw new CancelledException("ROM header invalid.");
				}

				// Find the load address for this page.
				int load_addr = header.load_addr & 0xFF00;
				Address addr = as.getAddress(header.load_addr & 0xFF00);
				if (load_addr != 0x8000) {
					// Check that there's a valid ROM header at the load address.
					header = new ROMHeader(provider, page_index + load_addr - 0x8000);
					if (!header.IsValid()) {
						throw new CancelledException("Load address ROM header invalid");
					}
				}

				// Offset data and length with respect to the load address.
				InputStream data = provider.getInputStream(page_index + load_addr - 0x8000);
				MemoryBlock blk = memory.createInitializedBlock("ROM_%d".formatted(page++), addr, data, 0x10000 - load_addr, monitor, true);
				blk.setPermissions(true, false, true);

				createData(program, blk.getStart(), ROM_HEADER, -1, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);

				length_remaining -= 0x8000;
				page_index += 0x8000;

				ProcessVector(program, blk, 0xFFFE, "RST");
				ProcessVector(program, blk, 0xFFFC, "NMI");
				ProcessVector(program, blk, 0xFFFA, "SWI");
				ProcessVector(program, blk, 0xFFF8, "IRQ");
			}
		} catch (Exception e) {
		    log.appendException(e);
		    throw new CancelledException("Loading failed: " + e.getMessage());
		}
	}

	private void ProcessVector(Program program, MemoryBlock blk, int address, String name) throws Exception {
		AddressSpace ovl = blk.getAddressRange().getAddressSpace();
		Address addr = ovl.getAddress(address);
		createData(program, addr, ptr, -1, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		program.getSymbolTable().createLabel(addr, name + "_VECTOR", SourceType.ANALYSIS);
		markAsFunction(program, name + "_" + blk.getName(), ovl.getAddress(program.getMemory().getShort(addr)));
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
