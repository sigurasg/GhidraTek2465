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

import java.awt.Component;

import javax.swing.BoxLayout;
import javax.swing.JComboBox;
import javax.swing.JPanel;

import ghidra.app.util.Option;

class ScopeKindOption extends Option {
	private final Component customEditor = createCustomEditor(this);

	public ScopeKindOption(String name, ScopeKind value) {
		super(name, ScopeKind.class, value, null, null);
	}

	public ScopeKindOption(String group, String name, ScopeKind value) {
		super(name, ScopeKind.class, value, null, group);
	}

	public ScopeKindOption(String name) {
		super(name, ScopeKind.class, null, null, null);
	}

	public ScopeKindOption(String name, ScopeKind value, String arg) {
		super(name, ScopeKind.class, value, arg, null);
	}

	public ScopeKindOption(String name, ScopeKind value, String arg, String group) {
		super(name, ScopeKind.class, value, arg, group);
	}

	@Override
	public Component getCustomEditorComponent() {
		return this.customEditor;
	}

	private static Component createCustomEditor(Option option) {
		var panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.PAGE_AXIS));

		var comboBox = new JComboBox();
		for (var kind : ScopeKind.values()) {
			comboBox.addItem(ROMUtils.getScopeKindName(kind));
		}
		comboBox.setSelectedItem(ROMUtils.getScopeKindName((ScopeKind) option.getValue()));

		comboBox.addActionListener(
			e -> option.setValue(ScopeKind.values()[comboBox.getSelectedIndex()]));

		panel.add(comboBox);
		return panel;
	}

	@Override
	public Option copy() {
		return new ScopeKindOption(this.getName(), (ScopeKind) this.getValue(), this.getArg(),
			this.getGroup());
	}

}