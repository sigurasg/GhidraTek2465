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
import ghidra.app.cmd.function.CreateFunctionCmd;
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
 * This analyzer sets the thunk function of ROM banking thunks to the ultimate service
 * function by looking at the listing in the destination bank. This greatly aids reversing,
 * as the decompiler will display the ultimate destination function, rather than the
 * banking thunk.
 *
 * This implementation relies on the convention that banking functions be named with
 * the prefix "BANK_" suffixed with the name of the destination memory block.
 * Example:
 *   "BANK_U2160-0".
 *
 * The banking functions must be of the form
 *   JSR BANK_<dest bank>
 *
 * or in the case of the 2465B (early and late):
 *   DES
 *   JSR BANK_<dest bank>
 *
 * and the destination bank must contain
 *   JSR SERVICE_FUNCTION
 *
 * at the address immediately succeeding the JSR BANK_ instruction in the
 * the destination bank.
 *
 * This analyzer can also walk back to references to any BANK_* function and
 * mark the (supposed) banking thunk as function, which helps auto analysis
 * move forward.
 */
public class Tek2465BankingAnalyzer extends AbstractAnalyzer {
	private static final String OPTION_SCOPE_KIND = "Scope kind";
	private static final String OPTION_REPROCESS_THUNKS = "Reprocess existing thunks";
	private static final String OPTION_MARK_BANK_CALLER_FUNCTIONS =
		"Mark all callers of BANK_* as functions";

	public Tek2465BankingAnalyzer() {
		super("Tek2465 Banking Analyzer",
			"Converts Tek2465 ROM banking functions to thunks pointing to the service function.",
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
			// There's no banking on the 2465.
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
		options.registerOption(OPTION_MARK_BANK_CALLER_FUNCTIONS, markBankCallersAsFunctions, null,
			"Mark all callers of BANK_* functions as functions themselves.");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		scopeKind = options.getEnum(OPTION_SCOPE_KIND, scopeKind);
		reprocessThunks = options.getBoolean(OPTION_REPROCESS_THUNKS, reprocessThunks);
		markBankCallersAsFunctions =
			options.getBoolean(OPTION_MARK_BANK_CALLER_FUNCTIONS, markBankCallersAsFunctions);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		var functions = program.getFunctionManager().getFunctionsOverlapping(set);

		// Keep track of any functions that need to be revisited later.
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
		if (f.getName().startsWith("BANK_") && markBankCallersAsFunctions) {
			markCallersAsFunctions(f, monitor, log);
		}

		return maybeConvertBankingFunctionToThunk(f, monitor, log);
	}

	private void markCallersAsFunctions(Function f, TaskMonitor monitor, MessageLog log) {
		var program = f.getProgram();
		var referenceManager = program.getReferenceManager();
		var functionManager = program.getFunctionManager();

		AddressSet functionsToCreate = new AddressSet();
		for (var ref : referenceManager.getReferencesTo(f.getEntryPoint())) {
			if (ref.getReferenceType().isCall()) {
				int thunkLength = 8; // Two JSR and a JMP in 2465As.
				Address callAddress = ref.getFromAddress();
				if (scopeKind != ScopeKind.TEK2465A) {
					// The banking thunks in the early and late Bs start with a DES instruction.
					callAddress = callAddress.subtract(1);
					thunkLength += 1;
				}

				// Try the easy way first.
				Function thunk = markOrGetFunction(callAddress, functionManager, log);
				if (thunk == null) {
					// The easy way didn't work, schedule a command to try harder.
					functionsToCreate.add(callAddress);
				}
			}
		}

		if (!functionsToCreate.isEmpty()) {
			// Schedule a command to try harder for the functions that didn't work out above.
			CreateFunctionCmd cmd = new CreateFunctionCmd(functionsToCreate);
			cmd.applyTo(program, monitor);
		}

	}

	/*
	 * Returns true if this needs to re-run.
	 */
	private boolean maybeConvertBankingFunctionToThunk(Function f, TaskMonitor monitor,
			MessageLog log) {
		// Don't process functions that are already thunks, unless explicitly set to do so.
		if (!reprocessThunks && f.isThunk()) {
			return false;
		}

		// See whether the first instruction is "JSR".
		Program program = f.getProgram();
		Listing listing = program.getListing();
		FunctionManager functionManager = program.getFunctionManager();

		Address destAddr = getBankingFunctionDestAddr(f, log);
		if (destAddr == null) {
			return false;
		}

		Instruction serviceCall = listing.getInstructionAt(destAddr);
		if (serviceCall == null) {
			// Initiate dissassembly at destAddr.
			DisassembleCommand cmd = new DisassembleCommand(destAddr, null, true);
			cmd.applyTo(program, monitor);
			// Just return here as the disassembly is asynchronous, but
			// ask the caller to reschedule visiting this function.
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
		Function service = markOrGetFunction(serviceAddress, functionManager, log);
		if (service != null) {
			// Success, set the service function.
			f.setThunkedFunction(service);
		}
		else {
			log.appendMsg(
				"Unable to get service function for JSR at %s.".formatted(destAddr.toString()));
		}

		return false;
	}

	/*
	 * For a banking function f, returns the address of the call to the service
	 * function in the destination bank. Returns null if f is not a banking function.
	 */
	private Address getBankingFunctionDestAddr(Function f, MessageLog log) {
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

		Instruction bankingCall = listing.getInstructionAt(instructionAddr);
		if (bankingCall == null || !bankingCall.getMnemonicString().equals("JSR")) {
			return null;
		}
		// Lookup the callee function.
		var refs = bankingCall.getOperandReferences(0);
		if (refs.length != 1) {
			return null;
		}
		Function callee = program.getFunctionManager().getFunctionAt(refs[0].getToAddress());
		if (callee == null) {
			return null;
		}
		if (!callee.getName().startsWith("BANK_")) {
			return null;
		}

		// Resolve the tail of the function name to the destination memory block.
		String destBank = callee.getName().substring(5);
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(destBank);
		if (block == null) {
			log.appendMsg("Not a memory block: " + destBank);
			return null;
		}

		// Construct the address of the fall through instruction in the
		// destination address space.
		return block.getAddressRange()
				.getAddressSpace()
				.getAddress(bankingCall.getFallThrough().getOffset());
	}

	private Function markOrGetFunction(Address entryPoint, FunctionManager functionManager,
			MessageLog log) {
		Function function = functionManager.getFunctionAt(entryPoint);
		if (function == null) {
			try {
				function = functionManager.createFunction(null, entryPoint,
					new AddressSet(entryPoint, entryPoint),
					SourceType.ANALYSIS);
			}
			catch (InvalidInputException e) {
				log.appendException(e);
			}
			catch (OverlappingFunctionException e) {
				// The caller will deal with the null return.
			}
		}

		return function;
	}

	private boolean reprocessThunks = false;
	private boolean markBankCallersAsFunctions = true;
	private ScopeKind scopeKind = ScopeKind.UNKNOWN;
}
