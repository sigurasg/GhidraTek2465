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

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * This analyzer sets the thunk function of ROM paging functions to the service
 * function by looking at the JSR instruction in the destination page.
 * This relies on teh convention that paging functions are named with the prefix
 * "PAGE_" suffixed with the name of the destination memory block. Example
 * "PAGE_U2160-0".
 *
 * The paging functions must be of the form
 *   JSR PAGE_<dest page>
 *
 * and the destination page must contain
 *   JSR SERVICE_FUNCTION
 *
 * at the address immediately succeeding the JSR PAGE_ instruction, in the
 * the destination page.
 */
public class Tek2465PagingThunkAnalyzer extends AbstractAnalyzer {
	public Tek2465PagingThunkAnalyzer() {
		// TODO: Name the analyzer and give it a description.
		super("Tek2465 Thunk Resolver",
			"Converts Tek2465 ROM paging functions to thunks pointing to the service function.",
			AnalyzerType.FUNCTION_ANALYZER);

		setSupportsOneTimeAnalysis(true);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		// TODO(siggi): Enable by default once this is proven useful.
		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (program.getLanguageID().equals(new LanguageID("MC6800:BE:16:default"))) {
			return true;
		}

		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here
		// TODO: Maybe add an option to also process existing thunks?
		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		var functions = program.getFunctionManager().getFunctionsOverlapping(set);
		functions.forEachRemaining(f -> maybeConvertPagingFunctionToThunk(f, monitor, log));

		return true;
	}

	private void maybeConvertPagingFunctionToThunk(Function f, TaskMonitor monitor,
			MessageLog log) {
		// Don't process functions that are already thunks.
		if (f.isThunk()) {
			return;
		}

		// See whether the first instruction is "JSR".
		Program program = f.getProgram();
		Listing listing = program.getListing();
		Instruction pagingCall = listing.getInstructionAt(f.getEntryPoint());
		if (pagingCall == null || !pagingCall.getMnemonicString().equals("JSR")) {
			return;
		}
		// Lookup the callee function.
		var refs = pagingCall.getOperandReferences(0);
		if (refs.length != 1) {
			return;
		}
		FunctionManager functionManager = program.getFunctionManager();
		Function callee = functionManager.getFunctionAt(refs[0].getToAddress());
		if (callee == null) {
			return;
		}
		if (!callee.getName().startsWith("PAGE_")) {
			return;
		}

		// Resolve the tail of the function name to the destination memory block.
		String destPage = callee.getName().substring(5);
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(destPage);
		if (block == null) {
			return;
		}

		// Construct the address of the fallthrough instruction in the
		// destination address space.
		Address destAddr =
			block.getAddressRange()
					.getAddressSpace()
					.getAddress(pagingCall.getFallThrough().getOffset());

		Instruction serviceCall = listing.getInstructionAt(destAddr);
		if (serviceCall == null) {
			// Mark destAddr for disassembly.
			DisassembleCommand cmd =
				new DisassembleCommand(new AddressSet(destAddr, destAddr), null, true);
			cmd.applyTo(program, monitor);
		}

		// Try again (is this how it works?).
		serviceCall = listing.getInstructionAt(destAddr);
		if (serviceCall == null) {
			return;
		}
		if (!serviceCall.getMnemonicString().equals("JSR")) {
			return;
		}

		refs = serviceCall.getOperandReferences(0);
		if (refs.length != 1) {
			return;
		}

		// Get the service function.
		Address serviceAddress = refs[0].getToAddress();
		Function service = functionManager.getFunctionAt(serviceAddress);
		if (service == null) {
			// Try to create a marker for the service function.
			try {
				service = functionManager.createFunction(null, serviceAddress,
					new AddressSet(serviceAddress, serviceAddress),
					SourceType.ANALYSIS);
			}
			catch (InvalidInputException | OverlappingFunctionException e) {
				log.appendException(e);
				return;
			}
		}

		// Success, set the service function.
		f.setThunkedFunction(service);
	}
}
