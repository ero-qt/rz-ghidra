// SPDX-FileCopyrightText: 2026 ero-qt
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RizinPRINTCSHARP_H
#define RZ_GHIDRA_RizinPRINTCSHARP_H

#include "RizinPrintC.h"
#include "rz_ghidra.h"

#include <map>
#include <set>
#include <string>

/// \brief Prints a function of a C# program that a compiler like IL2CPP turned into native code
///
/// The printer builds on the C printer like Ghidra's PrintJava. It asks RzGhidraCSharpNames what a function, a global
/// or a struct is in C#, and writes calls, member access and types the way C# does. Code that C# doesn't have a form
/// for stays C.
class RizinPrintCSharp : public RizinPrintC
{
	private:
		/// A copy of a function of the names, whose texts only live until the next callback
		struct Function
		{
			RzGhidraCSharpKind kind;
			std::string type;
			std::string name;
			bool isStatic;
			int parameters;
			const ghidra::Varnode *instance = nullptr; ///< the global of a generic method's instance that gave the type
			bool isFromInstance = false; ///< whether the function is the method of that global, not the call's target
		};

		/// A copy of a global of the names
		struct Global
		{
			std::string text;
			std::string type;
			bool hasMethod;
			Function method;
		};

		static ghidra::OpToken throw_op; ///< The \e throw keyword before its value

		const RzGhidraCSharpNames *names;
		std::map<ghidra::uint8, std::string> typeLinks; ///< struct names by the ids of the types that the code names
		std::set<ghidra::uintm> propertyCalls; ///< the calls of accessors that the code writes as their property's name
		std::map<ghidra::uintm, unsigned int> sharerCalls; ///< the methods that calls of shared code read as, by time

		bool findFunction(const ghidra::Address &addr, Function &function) const;
		bool findCallee(const ghidra::PcodeOp *op, Function &function) const;
		bool isSharedConstructor(const ghidra::PcodeOp *op) const;
		bool isConstructorCall(const ghidra::PcodeOp *op) const;
		bool fitsCall(const ghidra::PcodeOp *op, const RzGhidraCSharpSharer &sharer) const;
		bool findSharer(const ghidra::PcodeOp *op, Function &function, unsigned int &index) const;
		bool findGlobal(const ghidra::Varnode *vn, Global &global) const;
		void pushTypeOf(const ghidra::PcodeOp *op, const Function &callee);
		void pushConstructorChain(const ghidra::PcodeOp *op, const Function &callee, int first);
		const RzGhidraCSharpType *findType(const ghidra::Datatype *ct) const;
		std::string typeName(const ghidra::Datatype *ct);
		bool isInstanceMethod(const ghidra::PcodeOp *op) const;
		bool isThis(const ghidra::Varnode *vn, const ghidra::PcodeOp *op) const;
		const ghidra::PcodeOp *findConstructor(const ghidra::PcodeOp *allocation) const;
		const ghidra::PcodeOp *findAllocation(const ghidra::PcodeOp *constructor) const;
		bool isHiddenStatement(const ghidra::PcodeOp *op) const;
		bool isCallByNumber(const ghidra::PcodeOp *op) const;
		bool isFlagStore(const ghidra::PcodeOp *op) const;
		bool isRuntimeCheck(const ghidra::FlowBlock *body) const;
		void pushReceiver(const ghidra::PcodeOp *op, const Function &callee);
		void pushMember(const ghidra::PcodeOp *op, const Function &callee, bool isProperty = false);
		void pushArguments(const ghidra::PcodeOp *op, int first, int count);
		bool pushOperator(const ghidra::PcodeOp *op, const Function &callee, int first);
		void pushRaise(const ghidra::PcodeOp *op, const Function &callee);
		bool pushItems(const ghidra::PcodeOp *op, const ghidra::TypePointer *pointer);

	protected:
		void pushTypeStart(const ghidra::Datatype *ct, bool noident) override;
		void pushSymbol(const ghidra::Symbol *sym, const ghidra::Varnode *vn, const ghidra::PcodeOp *op) override;

	public:
		RizinPrintCSharp(ghidra::Architecture *g, const RzGhidraCSharpNames *names, const std::string &nm = "rizin-csharp-language");

		/// Returns the struct names by the ids of the types that the printed code names
		const std::map<ghidra::uint8, std::string> &getTypeLinks() const { return typeLinks; }

		/// Returns the calls of accessors that the printed code writes as their property's name, by the calls' times
		const std::set<ghidra::uintm> &getPropertyCalls() const { return propertyCalls; }

		/// Returns the indexes of the methods that the printed calls of shared code read as, by the calls' times
		const std::map<ghidra::uintm, unsigned int> &getSharerCalls() const { return sharerCalls; }

		void resetDefaults() override;
		void adjustTypeOperators() override;
		void emitBlockBasic(const ghidra::BlockBasic *bb) override;
		void emitBlockIf(const ghidra::BlockIf *bl) override;
		void opCall(const ghidra::PcodeOp *op) override;
		void opPtrsub(const ghidra::PcodeOp *op) override;
};

#endif //RZ_GHIDRA_RizinPRINTCSHARP_H
