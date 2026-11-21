// SPDX-FileCopyrightText: 2024 Crabtux <crabtux@mail.ustc.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RizinLoadImage.h"
#include "RizinUtils.h"
#include "PcodeFixupPreprocessor.h"

#include <funcdata.hh>
#include <flow.hh>
#include <override.hh>

using namespace ghidra;

void PcodeFixupPreprocessor::fixupSharedReturnJumpToRelocs(RzAnalysisFunction *function, Funcdata *func, RzCore *core, RizinArchitecture &arch)
{
	RzList *xrefs = rz_analysis_function_get_xrefs_from(function);
	rz_list_foreach_cpp<RzAnalysisXRef>(xrefs, [&](RzAnalysisXRef *xref){
		// To ensure the instruction is a `jmp` instruction
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_CODE)
		{
			// If the target location is a imported function, then do the patch.
			RzBinReloc *reloc = rz_core_get_reloc_to(core, xref->to);
			if (reloc != nullptr && reloc->import != nullptr)
				func->getOverride().insertFlowOverride(Address(arch.getDefaultCodeSpace(), xref->from), Override::CALL_RETURN);
		}
	});
	rz_list_free(xrefs);

	// Marks a jump at the end of a block to the start of another function as a call and a return, because it's a
	// tail call and the code of the other function doesn't belong to this one.
	rz_pvector_foreach_cpp<RzAnalysisBlock>(function->bbs, [&](RzAnalysisBlock *block) {
		RzAnalysisFunction *target = rz_analysis_get_function_at(core->analysis, block->jump);
		if (block->fail == UT64_MAX && block->ninstr > 0 && target != nullptr && target != function)
		{
			ut64 jump = rz_analysis_block_get_op_addr(block, block->ninstr - 1);
			func->getOverride().insertFlowOverride(Address(arch.getDefaultCodeSpace(), jump), Override::CALL_RETURN);
		}
		return true;
	});
}
