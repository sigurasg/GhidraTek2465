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

import java.io.IOException;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
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
	private static final String OPTION_SCOPE_KIND = "Scope kind";
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
		if (!program.getLanguageID().equals(new LanguageID("MC6800:BE:16:default"))) {
			return false;
		}
		scopeKind = getScopeKindFromProgram(program);
		if (scopeKind == ScopeKind.UNKNOWN || scopeKind == ScopeKind.TEK2465) {
			// There's no paging on the 2465.
			return false;
		}

		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// TODO(siggi): Should the scopeKind come from program here?
		options.registerOption(OPTION_SCOPE_KIND, scopeKind, null, "Scope Kind.");
		options.registerOption(OPTION_REPROCESS_THUNKS, reprocessThunks, null,
			"Reprocess existing thunks.");
		options.registerOption(OPTION_MARK_PAGE_CALLER_FUNCTIONS, markPageCallersAsFunctions, null,
			"Mark all callers of PAGE_* functions as functions themselves.");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		scopeKind = options.getEnum(OPTION_SCOPE_KIND, scopeKind);
		reprocessThunks = options.getBoolean(OPTION_REPROCESS_THUNKS, reprocessThunks);
		markPageCallersAsFunctions =
			options.getBoolean(OPTION_MARK_PAGE_CALLER_FUNCTIONS, markPageCallersAsFunctions);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		var functions = program.getFunctionManager().getFunctionsOverlapping(set);

		AddressSet toRevisit = new AddressSet();
		functions.forEachRemaining(f -> {
			if (processFunction(f, monitor, log)) {
				toRevisit.add(f.getBody());
			}
		});

		// Schedule a rerun over the functions that couldn't be completely processed.
		if (!toRevisit.isEmpty()) {
			var manager = AutoAnalysisManager.getAnalysisManager(program);
			manager.scheduleOneTimeAnalysis(this, toRevisit);
		}

		return true;
	}

	private ScopeKind getScopeKindFromProgram(Program program) {
		Memory memory = program.getMemory();
		for (MemoryBlock memoryBlock : memory.getBlocks()) {
			if (memoryBlock.isInitialized()) {
				try {
					ByteProvider byteProvider =
						MemoryByteProvider.createMemoryBlockByteProvider(memory, memoryBlock);
					int[] offsets = ROMUtils.findValidRomHeaders(byteProvider);

					for (int offset : offsets) {
						ROMHeader header = new ROMHeader(byteProvider, offset);

						ScopeKind scopeKind = ROMUtils.scopeKindFromPartNumber(header.partNumber);
						if (scopeKind != ScopeKind.UNKNOWN) {
							return scopeKind;
						}
					}
				}
				catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		return ScopeKind.UNKNOWN;
	}

	private boolean processFunction(Function f, TaskMonitor monitor,
			MessageLog log) {
		if (f.getName().startsWith("PAGE_") && markPageCallersAsFunctions) {
			markCallersAsFunctions(f, monitor, log);
		}

		return maybeConvertPagingFunctionToThunk(f, monitor, log);
	}

	private void markCallersAsFunctions(Function f, TaskMonitor monitor, MessageLog log) {
		var program = f.getProgram();
		var referenceManager = program.getReferenceManager();
		var functionManager = program.getFunctionManager();

		for (var ref : referenceManager.getReferencesTo(f.getEntryPoint())) {
			if (ref.getReferenceType().isCall()) {
				Address callAddress = ref.getFromAddress();
				if (scopeKind != ScopeKind.TEK2465A) {
					// The paging thunks in the early and late Bs start with a DES
					// instruction.
					callAddress = callAddress.subtract(1);
				}

				getOrMarkAsFunction(callAddress, functionManager, log);
			}
		}
	}

	/*
	 * Returns true if this needs to re-run.
	 */
	private boolean maybeConvertPagingFunctionToThunk(Function f, TaskMonitor monitor,
			MessageLog log) {
		// Don't process functions that are already thunks, unless explicitly set to do so.
		if (!reprocessThunks && f.isThunk()) {
			return false;
		}

		// See whether the first instruction is "JSR".
		Program program = f.getProgram();
		Listing listing = program.getListing();
		FunctionManager functionManager = program.getFunctionManager();

		Address destAddr = getPagingFunctionDestAddr(f, log);
		if (destAddr == null) {
			return false;
		}

		Instruction serviceCall = listing.getInstructionAt(destAddr);
		if (serviceCall == null) {
			// Initiate dissassembly at destAddr.
			DisassembleCommand cmd = new DisassembleCommand(destAddr, null, true);
			cmd.applyTo(program, monitor);
			// Just return here as the disassembly is asynchronous, but
			// ask caller to reschedule visiting this function.
			return true;
		}

		serviceCall = listing.getInstructionAt(destAddr);
		if (serviceCall == null) {
			return false;
		}
		if (!serviceCall.getMnemonicString().equals("JSR")) {
			return false;
		}

		var refs = serviceCall.getOperandReferences(0);
		if (refs.length != 1) {
			return false;
		}

		// Get the service function.
		Address serviceAddress = refs[0].getToAddress();
		Function service = getOrMarkAsFunction(serviceAddress, functionManager, log);
		if (service != null) {
			// Success, set the service function.
			f.setThunkedFunction(service);
		}

		return false;
	}

	private Address getPagingFunctionDestAddr(Function f, MessageLog log) {
		Program program = f.getProgram();
		Listing listing = program.getListing();

		Address instructionAddr = f.getEntryPoint();
		// For the Bs, walk over the DES instruction.
		if (scopeKind != ScopeKind.TEK2465A) {
			Instruction des = listing.getInstructionAt(instructionAddr);
			if (des == null || !des.getMnemonicString().equals("DES")) {
				return null;
			}
			instructionAddr = des.getFallThrough();
		}

		Instruction pagingCall = listing.getInstructionAt(instructionAddr);
		if (pagingCall == null || !pagingCall.getMnemonicString().equals("JSR")) {
			return null;
		}
		// Lookup the callee function.
		var refs = pagingCall.getOperandReferences(0);
		if (refs.length != 1) {
			return null;
		}
		Function callee = program.getFunctionManager().getFunctionAt(refs[0].getToAddress());
		if (callee == null) {
			return null;
		}
		if (!callee.getName().startsWith("PAGE_")) {
			return null;
		}

		// Resolve the tail of the function name to the destination memory block.
		String destPage = callee.getName().substring(5);
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(destPage);
		if (block == null) {
			log.appendMsg("Not a memory page: " + destPage);
			return null;
		}

		// Construct the address of the fallthrough instruction in the
		// destination address space.
		return block.getAddressRange()
				.getAddressSpace()
				.getAddress(pagingCall.getFallThrough().getOffset());
	}

	private Function getOrMarkAsFunction(Address serviceAddress, FunctionManager functionManager,
			MessageLog log) {
		Function function = functionManager.getFunctionContaining(serviceAddress);
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

	private boolean reprocessThunks = false;
	private boolean markPageCallersAsFunctions = true;
	private ScopeKind scopeKind = ScopeKind.UNKNOWN;
}
