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

import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Pointer16DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;

public class DataTypes {
	private static final CategoryPath PATH = new CategoryPath(CategoryPath.ROOT, "2465");
	// Types that are common across all scope kinds.
	public static final Pointer16DataType PTR = Pointer16DataType.dataType;
	public static final ByteDataType U8 = ByteDataType.dataType;
	public static final WordDataType U16 = WordDataType.dataType;
	public static final Structure ROM_HEADER;

	// Types that are per scope type.
	public final Structure ioRegion;
	public final Enum port1;

	public DataTypes(ScopeKind scopeKind) {
		StructureDataType port_1 = new StructureDataType("p1", 0);
		port_1.setPackingEnabled(true);
		// TODO(siggi): Same treatment for port2 & 3.
		try {
			port_1.addBitField(U8, 3, "mux_sel", null);
			switch (scopeKind) {
				case TEK2465:
					port_1.addBitField(U8, 1, "ea_c", null);
					port_1.addBitField(U8, 1, "ea_io", null);
					port_1.addBitField(U8, 1, "pwr_down", null);
					break;
				case TEK2465A:
					port_1.addBitField(U8, 1, "rom_select", null);
					port_1.addBitField(U8, 1, "page_select", null);
					port_1.addBitField(U8, 1, "pwr_down", null);
					break;
				case TEK2465B:
				case TEK2465B_LATE:
					port_1.addBitField(U8, 1, "pgsel0", null);
					port_1.addBitField(U8, 1, "pgsel1", null);
					port_1.addBitField(U8, 1, "pwr_down", null);
					port_1.addBitField(U8, 1, "pgsel2", null);
					break;
			}
		}
		catch (InvalidDataTypeException e) {
			e.printStackTrace();
		}

		boolean is2465 = scopeKind == ScopeKind.TEK2465;
		var coarse = new StructureDataType(PATH, "c", 0);
		coarse.add(array(U8, 64), is2465 ? "unused" : "dmux2_off", null);
		coarse.add(array(U8, 63), "dac_msb", null);
		coarse.add(U16, "dac_full", null);
		coarse.add(array(U8, 63), "dac_lsb", null);
		// Create a bit field for port 1.
		coarse.add(array(port_1, 64), "port_1_clk", null);
		coarse.add(array(U8, 64), "ros_1_clk", null);
		coarse.add(array(U8, 64), "ros_2_clk", null);
		coarse.add(array(U8, 64), "port_2_clk", null);

		Structure fine = new StructureDataType("f", 0);
		fine.add(U8, is2465 ? "unused" : "dmux2_on", null);
		fine.add(U8, "dmux0_off", null);
		fine.add(U8, "dmux0_on", null);
		fine.add(U8, "port_3_in", null);
		fine.add(U8, "dmux1_off", null);
		fine.add(U8, "dmux1_on", null);
		fine.add(U8, "led_clk", null);
		fine.add(U8, "disp_seq_clk", null);
		fine.add(U8, "atn_clk", null);
		fine.add(U8, "ch_2_pa_clk", null);
		fine.add(U8, "ch_1_pa_clk", null);
		fine.add(U8, "b_swp_clk", null);
		fine.add(U8, "a_swp_clk", null);
		fine.add(U8, "b_trig_clk", null);
		fine.add(U8, "a_trig_clk", null);
		fine.add(U8, "trig_stat_strb", null);
		coarse.add(array(fine, 4), "f", null);

		ioRegion = new StructureDataType(PATH, "io", 0);
		ioRegion.add(array(coarse, 4));

		port1 = new EnumDataType(PATH, "Port1", 1);
		port1.add("MUX_MASK", 0x7);
		port1.add("ROM_SELECT", 0x8);
		port1.add("PAGE_SELECT", 0x10);
		port1.add("PWR_DOWN", 0x20);
	}

	public void addAll(DataTypeManager manager) {
		var c = manager.createCategory(PATH);
		c.addDataType(ROM_HEADER, null);
		c.addDataType(ioRegion, null);
		c.addDataType(port1, null);
	}

	private static Array array(DataType d, int size) {
		return new ArrayDataType(d, size, -1);
	}

	static {
		// The standard ROM header of the era.
		ROM_HEADER = new StructureDataType(PATH, "ROMHeader", 0);
		ROM_HEADER.add(U16, "checksum", null);
		ROM_HEADER.add(U16, "part_number", null);
		ROM_HEADER.add(U8, "version", null);
		ROM_HEADER.add(U8, "version_compl", null);
		ROM_HEADER.add(U8, "load_addr", null);
		ROM_HEADER.add(U16, "tail_checksum", null);
		ROM_HEADER.add(U16, "rom_end", null);
		ROM_HEADER.add(U16, "next_rom", null);
		ROM_HEADER.add(U8, "zero", null);
		ROM_HEADER.add(U8, "effeff", null);
	}
}
