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

	private static final CategoryPath PATH = new CategoryPath(CategoryPath.ROOT, "2465a");
	public static final Pointer16DataType ptr = Pointer16DataType.dataType;
	public static final ByteDataType u8 = ByteDataType.dataType;
	public static final WordDataType u16 = WordDataType.dataType;
	public static final Structure ROM_HEADER;
	public static final Structure IO_REGION;
	public static final Enum PORT_1;

	static {
		// The standard ROM header of the era.
		ROM_HEADER = new StructureDataType(PATH, "ROMHeader", 0);
		ROM_HEADER.add(u16, "checksum", null);
		ROM_HEADER.add(u16, "part_number", null);
		ROM_HEADER.add(u8, "version", null);
		ROM_HEADER.add(u8, "version_compl", null);
		ROM_HEADER.add(u8, "load_addr", null);
		ROM_HEADER.add(u16, "tail_checksum", null);
		ROM_HEADER.add(u16, "rom_end", null);
		ROM_HEADER.add(u16, "next_rom", null);
		ROM_HEADER.add(u8, "zero", null);
		ROM_HEADER.add(u8, "effeff", null);

		// TODO(siggi): This needs to be per scope type.
		var coarse = new StructureDataType(PATH, "io", 0);
		coarse.add(array(u8, 64), "dmux2_off", null);
		coarse.add(array(u8, 63), "dac_msb", null);
		coarse.add(u16, "dac_full", null);
		coarse.add(array(u8, 63), "dac_lsb", null);
		// Create a bit field for port 1.
		StructureDataType port_1 = new StructureDataType("p1", 0);
		port_1.setPackingEnabled(true);
		try {
			port_1.addBitField(u8, 3, "mux_sel", null);
			port_1.addBitField(u8, 1, "rom_select", null);
			port_1.addBitField(u8, 1, "page_select", null);
			port_1.addBitField(u8, 1, "pwr_down", null);
		}
		catch (InvalidDataTypeException e) {
			e.printStackTrace();
		}

		coarse.add(array(port_1, 64), "port_1_clk", null);
		coarse.add(array(u8, 64), "ros_1_clk", null);
		coarse.add(array(u8, 64), "ros_2_clk", null);
		coarse.add(array(u8, 64), "port_2_clk", null);
		IO_REGION = new StructureDataType(PATH, "c", 0);
		IO_REGION.add(array(coarse, 4));

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

	public static Array array(DataType d, int size) {
		return new ArrayDataType(d, size, -1);
	}

	public static void addAll(DataTypeManager manager) {
		var c = manager.createCategory(PATH);
		c.addDataType(ROM_HEADER, null);
		c.addDataType(IO_REGION, null);
		c.addDataType(PORT_1, null);
	}
}
