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

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class ROMUtilsTest {
	@Test
	public void getScopeKindTest() {
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x1625), ROMUtils.ScopeKind.TEK2465);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x1626), ROMUtils.ScopeKind.TEK2465);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x1627), ROMUtils.ScopeKind.TEK2465);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x1628), ROMUtils.ScopeKind.TEK2465);

		assertEquals(ROMUtils.scopeKindFromPartNumber(0x3302), ROMUtils.ScopeKind.TEK2465A);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x3303), ROMUtils.ScopeKind.TEK2465A);

		assertEquals(ROMUtils.scopeKindFromPartNumber(0x5370), ROMUtils.ScopeKind.TEK2465B);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x5371), ROMUtils.ScopeKind.TEK2465B);

		assertEquals(ROMUtils.scopeKindFromPartNumber(0x5876), ROMUtils.ScopeKind.TEK2465B_LATE);
		assertEquals(ROMUtils.scopeKindFromPartNumber(0x5877), ROMUtils.ScopeKind.TEK2465B_LATE);
	}

	@Test
	public void getScopeKindNameTest() {
		assertEquals("Tek2465", ROMUtils.getScopeKindName(ROMUtils.ScopeKind.TEK2465));
		assertEquals("Tek2465A", ROMUtils.getScopeKindName(ROMUtils.ScopeKind.TEK2465A));
		assertEquals("Tek2465B", ROMUtils.getScopeKindName(ROMUtils.ScopeKind.TEK2465B));
		assertEquals("Tek2465B SN>B050000", ROMUtils.getScopeKindName(ROMUtils.ScopeKind.TEK2465B_LATE));
	}
}
