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
	private static final String OPTION_REPROCESS_THUNKS = "Reprocess existing thunks";
	private static final String OPTION_MARK_PAGE_CALLER_FUNCTIONS =
		"Mark all callers of PAGE_* as functions";

	public Tek2465PagingThunkAnalyzer() {
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
		options.registerOption(OPTION_REPROCESS_THUNKS, reprocessThunks, null,
			"Reprocess existing thunks.");
		options.registerOption(OPTION_MARK_PAGE_CALLER_FUNCTIONS, markPageCallersAsFunctions, null,
			"Mark all callers of PAGE_* functions as functions themselves.");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		reprocessThunks = options.getBoolean(OPTION_REPROCESS_THUNKS, reprocessThunks);
		markPageCallersAsFunctions =
			options.getBoolean(OPTION_MARK_PAGE_CALLER_FUNCTIONS, markPageCallersAsFunctions);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		var functions = program.getFunctionManager().getFunctionsOverlapping(set);
		functions.forEachRemaining(f -> processFunction(f, monitor, log));

		return true;
	}

	private void processFunction(Function f, TaskMonitor monitor,
			MessageLog log) {
		if (f.getName().startsWith("PAGE_") && markPageCallersAsFunctions) {
			markCallersAsFunctions(f, monitor, log);
		}

		maybeConvertPagingFunctionToThunk(f, monitor, log);
	}

	private void markCallersAsFunctions(Function f, TaskMonitor monitor, MessageLog log) {
		var program = f.getProgram();
		var referenceManager = program.getReferenceManager();
		var functionManager = program.getFunctionManager();

		for (var ref : referenceManager.getReferencesTo(f.getEntryPoint())) {
			if (ref.getReferenceType().isCall()) {
				getOrMarkAsFunction(ref.getFromAddress(), functionManager, log);
			}
		}
	}

	private void maybeConvertPagingFunctionToThunk(Function f, TaskMonitor monitor,
			MessageLog log) {
		// Don't process functions that are already thunks, unless explicitly set to do so.
		if (!reprocessThunks && f.isThunk()) {
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
			// Initiate dissassembly at destAddr.
			DisassembleCommand cmd = new DisassembleCommand(destAddr, null, true);
			cmd.applyTo(program, monitor);
			// Just return here as the disassembly is asynchronous.
			// TODO(siggi): How to schedule a revisit of this function?
			return;
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
		Function service = getOrMarkAsFunction(serviceAddress, functionManager, log);
		if (service != null) {
			// Success, set the service function.
			f.setThunkedFunction(service);
		}
	}

	private Function getOrMarkAsFunction(Address serviceAddress, FunctionManager functionManager,
			MessageLog log) {
		Function function = functionManager.getFunctionAt(serviceAddress);
		if (function == null) {
			try {
				function = functionManager.createFunction(null, serviceAddress,
					new AddressSet(serviceAddress, serviceAddress),
					SourceType.ANALYSIS);
			}
			catch (InvalidInputException | OverlappingFunctionException e) {
				log.appendException(e);
			}
		}

		return function;
	}

	boolean reprocessThunks = false;
	boolean markPageCallersAsFunctions = true;
}
