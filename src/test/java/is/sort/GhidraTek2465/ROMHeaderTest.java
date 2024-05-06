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

package is.sort.GhidraTek2465;

import java.io.IOException;

import org.junit.Test;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;

public class ROMHeaderTest {
	@Test
	public void validHeaderTest() throws IOException {
		byte header[] = {
				0x12, 0x23,  			// Checksum.
				0x33, 0x02,  			// Part number.
				0x06, ~0x06, 			// Version and complement.
				(byte)0x80,				// Load address.
				(byte)0xCC, 0x00,  		// Load address and unknown.
				(byte)0xff, (byte)0xff, // ROM end.
				0x00, 0x00,  			// Next ROM.
				0x00, (byte)0xff   		// Trailer.
		};
		ByteProvider provider = new ByteArrayProvider(header);
		ROMHeader romHeader = new ROMHeader(provider, 0);

		assert romHeader.IsValid();

		assert romHeader.getLoadAddress() == 0x8000;
		assert romHeader.getByteSize() == 0x8000;
	}
}
