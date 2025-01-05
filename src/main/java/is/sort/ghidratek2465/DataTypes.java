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
	public final Enum port1Enum;

	public DataTypes(ScopeKind scopeKind) {
		StructureDataType port1 = new StructureDataType(PATH, "p1", 0);
		port1.setPackingEnabled(true);
		try {
			port1.addBitField(U8, 3, "mux_sel", null);
			switch (scopeKind) {
				case TEK2465:
					port1.addBitField(U8, 1, "ea_c", null);
					port1.addBitField(U8, 1, "ea_io", null);
					port1.addBitField(U8, 1, "pwr_down", null);
					break;
				case TEK2465A:
					port1.addBitField(U8, 1, "rom_select", null);
					port1.addBitField(U8, 1, "page_select", null);
					port1.addBitField(U8, 1, "pwr_down", null);
					break;
				case TEK2465B:
				case TEK2465B_LATE:
					port1.addBitField(U8, 1, "pgsel0", null);
					port1.addBitField(U8, 1, "pgsel1", null);
					port1.addBitField(U8, 1, "pwr_down", null);
					port1.addBitField(U8, 1, "pgsel2", null);
					break;
				case UNKNOWN:
					break;
			}
		}
		catch (InvalidDataTypeException e) {
			e.printStackTrace();
		}

		StructureDataType port2 = new StructureDataType(PATH, "p2", 0);
		port2.setPackingEnabled(true);
		try {
			switch (scopeKind) {
				case TEK2465:
					port2.addBitField(U8, 1, "led_data", null);
					port2.addBitField(U8, 1, "oea_clk", null);
					port2.addBitField(U8, 1, "attn_strb", null);
					port2.addBitField(U8, 1, "u2408_inh", null);
					port2.addBitField(U8, 1, "u2418_inh", null);
					port2.addBitField(U8, 1, "trig_led", null);
					break;
				case TEK2465A:
				case TEK2465B:
				case TEK2465B_LATE:
					port2.addBitField(U8, 1, "led_data", null);
					port2.addBitField(U8, 1, "u2501_inh", null);
					port2.addBitField(U8, 1, "attn_strb", null);
					port2.addBitField(U8, 1, "u2601_inh", null);
					port2.addBitField(U8, 1, "u2401_inh", null);
					port2.addBitField(U8, 1, "trig_led", null);
					break;
				case UNKNOWN:
					break;
			}
		}
		catch (InvalidDataTypeException e) {
			e.printStackTrace();
		}

		StructureDataType port3 = new StructureDataType(PATH, "p3", 0);
		port3.setPackingEnabled(true);
		try {
			switch (scopeKind) {
				case TEK2465:
					port3.addBitField(U8, 1, "tso", null);
					port3.addBitField(U8, 1, "comp", null);
					port3.addBitField(U8, 1, "ro_do", null);
					port3.addBitField(U8, 1, "ro_on", null);
					port3.addBitField(U8, 1, "oea_out", null);
					port3.addBitField(U8, 1, "mux_out", null);
					break;
				case TEK2465A:
				case TEK2465B:
				case TEK2465B_LATE:
					// TODO(siggi): This needs verifying.
					port3.addBitField(U8, 1, "tso", null);
					port3.addBitField(U8, 1, "comp", null);
					port3.addBitField(U8, 1, "ro_do", null);
					port3.addBitField(U8, 1, "45_65_id", null);
					port3.addBitField(U8, 1, "step_switch", null);
					port3.addBitField(U8, 1, "mux_out", null);
					port3.addBitField(U8, 1, "beam_find", null);
					port3.addBitField(U8, 1, "65_67_id", null);
					break;
				case UNKNOWN:
					break;
			}
		}
		catch (InvalidDataTypeException e) {
			e.printStackTrace();
		}

		boolean is2465 = scopeKind == ScopeKind.TEK2465;
		switch (scopeKind) {
			case TEK2465:
			case TEK2465A:
			case TEK2465B: {
				// These are all quite similar.
				var coarse = new StructureDataType(PATH, "c", 0);
				coarse.add(array(U8, 64), is2465 ? "unused" : "dmux2_off", null);
				coarse.add(array(U8, 63), "dac_msb", null);
				coarse.add(U16, "dac_full", null);
				coarse.add(array(U8, 63), "dac_lsb", null);
				coarse.add(array(port1, 64), "port_1_clk", null);
				coarse.add(array(U8, 64), "ros_1_clk", null);
				coarse.add(array(U8, 64), "ros_2_clk", null);
				coarse.add(array(port2, 64), "port_2_clk", null);

				Structure fine = new StructureDataType(PATH, "f", 0);
				fine.add(U8, is2465 ? "unused" : "dmux2_on", null);
				fine.add(U8, "dmux0_off", null);
				fine.add(U8, "dmux0_on", null);
				fine.add(port3, "port_3_in", null);
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
				ioRegion.add(array(coarse, 4), "c", null);
				break;
			}

			case TEK2465B_LATE: {
				// The 2465B late version has a wholly different IO layout.
				Structure fine = new StructureDataType(PATH, "f", 0);
				fine.add(U8, "dac_msb_clk", null);
				fine.add(U8, "dac_lsb_clk", null);
				fine.add(port1, "port_1_clk", null);
				fine.add(port2, "port_2_clk", null);
				fine.add(port3, "port_3_clk", null);
				fine.add(U8, "ros_1_clk", null);
				fine.add(U8, "ros_2_clk", null);
				fine.add(U8, "disp_sec_clk", null);
				fine.add(U8, "attn_clk", null);
				fine.add(U8, "ch_2_pa_clk", null);
				fine.add(U8, "ch_1_pa_clk", null);
				fine.add(U8, "b_swp_clk", null);
				fine.add(U8, "a_swp_clk", null);
				fine.add(U8, "b_trig_clk", null);
				fine.add(U8, "a_trig_clk", null);
				fine.add(U8, "trig_stat_strb", null);

				var coarse = new StructureDataType(PATH, "c", 0);
				coarse.add(array(U8, 16), "port_4_clk", null);
				coarse.add(array(U8, 16), "led_clk", null);
				coarse.add(array(U8, 16), "ext_fp_clk", null);
				coarse.add(array(U8, 16), "dmux0_on", null);
				coarse.add(array(U8, 16), "dmux1_on", null);
				coarse.add(array(U8, 16), "dmux2_on", null);
				coarse.add(array(U8, 16), "dmux_off", null);
				coarse.add(fine, "f", null);
				ioRegion = new StructureDataType(PATH, "io", 0);
				ioRegion.add(array(coarse, 8), "m", null);
				break;
			}
			default:
				ioRegion = null;
				break;
		}

		port1Enum = new EnumDataType(PATH, "PORT1", 1);
		port1Enum.add("MUX_MASK", 0x7);
		if (is2465) {
			port1Enum.add("ROM_SELECT", 0x8);
			port1Enum.add("PAGE_SELECT", 0x10);
		}
		port1Enum.add("PWR_DOWN", 0x20);
	}

	public void addAll(DataTypeManager manager) {
		var c = manager.createCategory(PATH);
		c.addDataType(ROM_HEADER, null);
		c.addDataType(ioRegion, null);
		c.addDataType(port1Enum, null);
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
