// SPDX-FileCopyrightText: 2026 ero-qt
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "RizinPrintCSharp.h"

#include <algorithm>

#include <architecture.hh>
#include <block.hh>
#include <funcdata.hh>
#include <varnode.hh>

using namespace ghidra;

OpToken RizinPrintCSharp::throw_op = { "", "", 2, 2, false, OpToken::space, 1, 0, (OpToken *)0 };

static const std::string KEYWORD_THIS = "this";
static const std::string KEYWORD_BASE = "base";
static const std::string KEYWORD_THROW = "throw";

RizinPrintCSharp::RizinPrintCSharp(Architecture *g, const RzGhidraCSharpNames *names, const string &nm)
	: RizinPrintC(g, nm), names(names)
{
	resetDefaults();
}

void RizinPrintCSharp::resetDefaults()
{
	RizinPrintC::resetDefaults();
	nullToken = "null";
	option_NULL = true;
	option_convention = false;
	// A call that doesn't return reads as a throw, which doesn't need Ghidra's warning
	setInstructionComment(getInstructionComment() & ~(uint4)Comment::warning);
}

void RizinPrintCSharp::docFunction(const Funcdata *fd)
{
	printed = fd;
	RizinPrintC::docFunction(fd);
	printed = nullptr;
}

void RizinPrintCSharp::adjustTypeOperators()
{
	RizinPrintC::adjustTypeOperators();
	scope.print1 = ".";
	pointer_member.print1 = ".";
}

bool RizinPrintCSharp::findFunction(const Address &addr, Function &function) const
{
	const RzGhidraCSharpFunction *found = names && names->function ? names->function(names->user, addr.getOffset()) : nullptr;
	if(!found)
		return false;
	function.kind = found->kind;
	function.type = found->type ? found->type : "";
	function.name = found->name ? found->name : "";
	function.isStatic = found->is_static;
	function.parameters = (int)found->parameters;
	return true;
}

/// Finds the global of the names that a variable is, also behind a cast.
bool RizinPrintCSharp::findGlobal(const Varnode *vn, Global &global) const
{
	if(!names || !names->global)
		return false;
	while(vn->isImplied() && vn->isWritten() && vn->getDef()->code() == CPUI_CAST)
		vn = vn->getDef()->getIn(0);
	if(vn->isConstant() || !vn->isPersist())
		return false;

	const Symbol *sym = vn->getHigh()->getSymbol();
	SymbolEntry *entry = sym && sym->getScope()->isGlobal() ? sym->getFirstWholeMap() : nullptr;
	const RzGhidraCSharpGlobal *found = entry ? names->global(names->user, entry->getAddr().getOffset()) : nullptr;
	if(!found)
		return false;
	global.text = found->text ? found->text : "";
	global.type = found->type ? found->type : "";
	global.hasMethod = found->method != nullptr;
	if(found->method)
	{
		global.method.kind = found->method->kind;
		global.method.type = global.type;
		global.method.name = found->method->name ? found->method->name : "";
		global.method.isStatic = found->method->is_static;
		global.method.parameters = (int)found->method->parameters;
	}
	return true;
}

bool RizinPrintCSharp::findCallee(const PcodeOp *op, Function &function) const
{
	if(op->code() != CPUI_CALL)
		return false;
	const Varnode *callpoint = op->getIn(0);
	if(callpoint->getSpace()->getType() != IPTR_FSPEC)
		return false;
	return findFunction(FuncCallSpecs::getFspecFromConst(callpoint->getAddr())->getEntryAddress(), function);
}

/// Returns the name of the struct that a call's argument points to, also behind a cast, or an empty text.
static std::string pointedStruct(const Varnode *vn)
{
	while(vn->isImplied() && vn->isWritten() && vn->getDef()->code() == CPUI_CAST)
		vn = vn->getDef()->getIn(0);
	const Datatype *ct = vn->getHigh()->getType();
	if(ct->getMetatype() != TYPE_PTR)
		return "";
	const Datatype *pointed = ((const TypePointer *)ct)->getPtrTo();
	return pointed->getMetatype() == TYPE_STRUCT ? pointed->getName() : "";
}

/// Checks whether a method that shares the called code takes the call's arguments: their count with the object of an
/// instance method and the hidden last argument, and the struct of each argument that points to a struct where the
/// method's parameter points to one.
static bool takesArguments(const PcodeOp *op, const RzGhidraCSharpSharer &sharer)
{
	int first = sharer.function.is_static ? 1 : 2;
	if(op->numInput() - 1 != (int)sharer.function.parameters + first)
		return false;

	std::string structs = sharer.parameter_structs ? sharer.parameter_structs : "";
	size_t start = 0;
	for(int i = 1; i < op->numInput() - 1 && start <= structs.size(); ++i)
	{
		size_t end = std::min(structs.find(',', start), structs.size());
		std::string expected = structs.substr(start, end - start);
		start = end + 1;

		std::string actual = pointedStruct(op->getIn(i));
		if(!expected.empty() && !actual.empty() && actual != expected)
			return false;
	}
	return true;
}

/// Checks whether a constructor that shares the called code takes the call's arguments and is the constructor of the
/// call's object, because the object points to the constructor's own struct.
static bool constructsObject(const PcodeOp *op, const RzGhidraCSharpSharer &sharer)
{
	if(sharer.function.kind != RZ_GHIDRA_CSHARP_CONSTRUCTOR || sharer.function.is_static || !takesArguments(op, sharer))
		return false;

	std::string structs = sharer.parameter_structs ? sharer.parameter_structs : "";
	std::string own = structs.substr(0, structs.find(','));
	return !own.empty() && pointedStruct(op->getIn(1)) == own;
}

/// Checks whether a call of shared code is the call of a constructor that shares the code on the call's object.
bool RizinPrintCSharp::isSharedConstructor(const PcodeOp *op) const
{
	if(!names || !names->sharer || op->code() != CPUI_CALL || op->getIn(0)->getSpace()->getType() != IPTR_FSPEC)
		return false;

	uint8 addr = FuncCallSpecs::getFspecFromConst(op->getIn(0)->getAddr())->getEntryAddress().getOffset();
	for(ut32 i = 0;; ++i)
	{
		const RzGhidraCSharpSharer *sharer = names->sharer(names->user, addr, i);
		if(!sharer)
			return false;
		if(constructsObject(op, *sharer))
			return true;
	}
}

/// Checks whether a method that shares the called code fits the call. A constructor only fits a call on the object
/// that an allocation right before makes of the constructor's type, so the call reads as `new`.
bool RizinPrintCSharp::fitsCall(const PcodeOp *op, const RzGhidraCSharpSharer &sharer) const
{
	if(sharer.function.kind == RZ_GHIDRA_CSHARP_CONSTRUCTOR)
		return constructsObject(op, sharer) && findAllocation(op) != nullptr;
	return takesArguments(op, sharer);
}

/// Finds the method that a call of shared code reads as, among the methods that share the code and fit the call. Every
/// one of them runs the same code, so the call reads as an operator or a constructor when one fits, or else as the
/// only one that fits.
bool RizinPrintCSharp::findSharer(const PcodeOp *op, Function &function, unsigned int &index) const
{
	if(!names || !names->sharer || op->code() != CPUI_CALL || op->getIn(0)->getSpace()->getType() != IPTR_FSPEC)
		return false;

	uint8 addr = FuncCallSpecs::getFspecFromConst(op->getIn(0)->getAddr())->getEntryAddress().getOffset();
	int fitting = 0;
	bool isPreferred = false;
	for(ut32 i = 0;; ++i)
	{
		const RzGhidraCSharpSharer *sharer = names->sharer(names->user, addr, i);
		if(!sharer)
			break;
		if(isPreferred || !fitsCall(op, *sharer))
			continue;

		RzGhidraCSharpKind kind = sharer->function.kind;
		isPreferred = kind == RZ_GHIDRA_CSHARP_OPERATOR || kind == RZ_GHIDRA_CSHARP_CONSTRUCTOR;
		if(++fitting > 1 && !isPreferred)
			continue;
		function.kind = sharer->function.kind;
		function.type = sharer->function.type ? sharer->function.type : "";
		function.name = sharer->function.name ? sharer->function.name : "";
		function.isStatic = sharer->function.is_static;
		function.parameters = (int)sharer->function.parameters;
		index = sharer->index;
	}
	return isPreferred || fitting == 1;
}

const RzGhidraCSharpType *RizinPrintCSharp::findType(const Datatype *ct) const
{
	if(ct->getMetatype() != TYPE_STRUCT || !names || !names->type)
		return nullptr;
	return names->type(names->user, ct->getName().c_str());
}

/// Returns the C# name of a type, a keyword for a number of the type's size, and remembers the struct of a type
/// that the names know, so the code's parser can link the name.
std::string RizinPrintCSharp::typeName(const Datatype *ct)
{
	const RzGhidraCSharpType *type = findType(ct);
	if(type)
	{
		typeLinks[ct->getUnsizedId()] = ct->getName();
		return type->name;
	}

	int4 size = ct->getSize();
	switch(ct->getMetatype())
	{
		case TYPE_VOID:
			return "void";
		case TYPE_BOOL:
			return "bool";
		case TYPE_FLOAT:
			if(size == 4)
				return "float";
			if(size == 8)
				return "double";
			break;
		case TYPE_INT:
			if(ct->isCharPrint() && size == 2)
				return "char";
			if(size == 1)
				return "sbyte";
			if(size == 2)
				return "short";
			if(size == 4)
				return "int";
			if(size == 8)
				return "long";
			break;
		case TYPE_UINT:
		case TYPE_UNKNOWN:
			if(size == 1)
				return "byte";
			if(size == 2)
				return "ushort";
			if(size == 4)
				return "uint";
			if(size == 8)
				return "ulong";
			break;
		default:
			break;
	}
	return ct->getName().empty() ? genericTypeName(ct) : ct->getDisplayName();
}

void RizinPrintCSharp::pushTypeStart(const Datatype *ct, bool noident)
{
	vector<const Datatype *> typestack;
	buildTypeStack(ct, typestack);

	const Datatype *base = typestack.back();
	const RzGhidraCSharpType *type = findType(base);
	// A reference to an object is a pointer to its class's struct, which C# writes as the class
	if(type && type->is_object && typestack.size() > 1 && typestack[typestack.size() - 2]->getMetatype() == TYPE_PTR)
		typestack.erase(typestack.end() - 2);

	std::string name = typeName(base);
	pushOp(noident && typestack.size() == 1 ? &type_expr_nospace : &type_expr_space, (const PcodeOp *)0);
	pushAtom(Atom(name, typetoken, EmitMarkup::type_color, base));
	for(int4 i = (int4)typestack.size() - 2; i >= 0; --i)
	{
		switch(typestack[i]->getMetatype())
		{
			case TYPE_PTR:
				pushOp(&ptr_expr, (const PcodeOp *)0);
				break;
			case TYPE_ARRAY:
				pushOp(&array_expr, (const PcodeOp *)0);
				break;
			case TYPE_CODE:
				pushOp(&function_call, (const PcodeOp *)0);
				break;
			default:
				clear();
				throw LowlevelError("Bad type expression");
		}
	}
}

void RizinPrintCSharp::pushSymbol(const Symbol *sym, const Varnode *vn, const PcodeOp *op)
{
	// The first parameter of an instance method is the method's object, whatever its name in the signature
	if(sym->getCategory() == Symbol::function_parameter && sym->getCategoryIndex() == 0 && op && isInstanceMethod(op))
	{
		pushAtom(Atom(KEYWORD_THIS, vartoken, EmitMarkup::keyword_color, op, vn));
		return;
	}
	if(sym->getScope()->isGlobal() && names && names->global)
	{
		SymbolEntry *entry = sym->getFirstWholeMap();
		const RzGhidraCSharpGlobal *global = entry ? names->global(names->user, entry->getAddr().getOffset()) : nullptr;
		if(global && global->text)
		{
			std::string written(global->text);
			pushAtom(Atom(written, vartoken, EmitMarkup::global_color, op, vn));
			return;
		}
	}
	RizinPrintC::pushSymbol(sym, vn, op);
}

/// Returns whether the printer prints an instance method that the names know.
bool RizinPrintCSharp::isInstanceMethod(const PcodeOp *op) const
{
	Function current;
	bool isKnown = findFunction(op->getParent()->getFuncdata()->getAddress(), current);
	return isKnown && !current.isStatic && current.kind <= RZ_GHIDRA_CSHARP_OPERATOR;
}

/// Returns whether a variable is the object of the instance method that the printer prints, also behind a cast
/// to a base class's struct.
bool RizinPrintCSharp::isThis(const Varnode *vn, const PcodeOp *op) const
{
	if(!isInstanceMethod(op))
		return false;
	while(vn->isImplied() && vn->isWritten() && vn->getDef()->code() == CPUI_CAST)
		vn = vn->getDef()->getIn(0);
	const HighVariable *high = vn->getHigh();
	const Symbol *sym = high ? high->getSymbol() : nullptr;
	return sym && sym->getCategory() == Symbol::function_parameter && sym->getCategoryIndex() == 0;
}

/// Checks whether a call reads as a constructor's call, the way opCall() picks the called method: a known constructor,
/// the constructor of the hidden argument's method global when the names don't know the called code, or a constructor
/// that shares the called code.
bool RizinPrintCSharp::isConstructorCall(const PcodeOp *op) const
{
	if(op->code() != CPUI_CALL)
		return false;

	Function callee;
	bool isKnown = findCallee(op, callee);
	if(isKnown && callee.kind == RZ_GHIDRA_CSHARP_CONSTRUCTOR)
		return true;

	Global instance;
	const Varnode *last = op->numInput() > 1 ? op->getIn(op->numInput() - 1) : nullptr;
	bool hasInstance = last && findGlobal(last, instance) && instance.hasMethod;
	if(hasInstance)
		return !isKnown && instance.method.kind == RZ_GHIDRA_CSHARP_CONSTRUCTOR;
	return isSharedConstructor(op);
}

/// Returns the constructor's call on the object that a call allocates, when both are in 1 block, so they print as
/// 1 `new` expression at the constructor's call. The call can also be of code that the constructor shares.
const PcodeOp *RizinPrintCSharp::findConstructor(const PcodeOp *allocation) const
{
	const Varnode *object = allocation->getOut();
	if(!object)
		return nullptr;

	vector<const Varnode *> objects = { object };
	for(auto it = object->beginDescend(); it != object->endDescend(); ++it)
	{
		if((*it)->code() == CPUI_CAST && (*it)->getOut())
			objects.push_back((*it)->getOut());
	}
	for(const Varnode *vn : objects)
	{
		for(auto it = vn->beginDescend(); it != vn->endDescend(); ++it)
		{
			const PcodeOp *use = *it;
			if(isConstructorCall(use) && use->numInput() > 1 && use->getIn(1) == vn && use->getParent() == allocation->getParent())
				return use;
		}
	}
	return nullptr;
}

const PcodeOp *RizinPrintCSharp::findAllocation(const PcodeOp *constructor) const
{
	const Varnode *object = constructor->getIn(1);
	if(object->isWritten() && object->getDef()->code() == CPUI_CAST)
		object = object->getDef()->getIn(0);
	if(!object->isWritten())
		return nullptr;

	const PcodeOp *allocation = object->getDef();
	Function callee;
	bool isAllocation = findCallee(allocation, callee) && callee.kind == RZ_GHIDRA_CSHARP_OBJECT_NEW;
	return isAllocation && findConstructor(allocation) == constructor ? allocation : nullptr;
}

/// Returns whether a statement is bookkeeping of the runtime, which C# doesn't have a form for.
bool RizinPrintCSharp::isHiddenStatement(const PcodeOp *op) const
{
	Function callee;
	if(!findCallee(op, callee))
		return false;
	switch(callee.kind)
	{
		case RZ_GHIDRA_CSHARP_CLASS_INIT:
		case RZ_GHIDRA_CSHARP_WRITE_BARRIER:
		case RZ_GHIDRA_CSHARP_METADATA_INIT:
			return true;
		case RZ_GHIDRA_CSHARP_OBJECT_NEW:
			return findConstructor(op) != nullptr;
		default:
			return false;
	}
}

/// Returns whether a call passes nothing but numbers to a function that the names don't know, like the index of a
/// method's metadata that an older runtime fills its globals by.
bool RizinPrintCSharp::isCallByNumber(const PcodeOp *op) const
{
	Function callee;
	if(op->code() != CPUI_CALL || op->numInput() < 2 || findCallee(op, callee))
		return false;
	for(int4 i = 1; i < op->numInput(); ++i)
	{
		if(!op->getIn(i)->isConstant())
			return false;
	}
	return true;
}

/// Returns whether a statement sets a global at a fixed address to a number, like the flag of a runtime's check.
bool RizinPrintCSharp::isFlagStore(const PcodeOp *op) const
{
	if(op->code() == CPUI_COPY)
		return op->getIn(0)->isConstant() && op->getOut() && op->getOut()->isPersist();
	if(op->code() != CPUI_STORE || !op->getIn(2)->isConstant())
		return false;

	const Varnode *pointer = op->getIn(1);
	if(pointer->isConstant())
		return true;
	const PcodeOp *def = pointer->isWritten() ? pointer->getDef() : nullptr;
	return def && def->code() == CPUI_PTRSUB && def->getIn(0)->isConstant() && def->getIn(1)->isConstant();
}

/// Returns whether a type points to the runtime's metadata of a class or a method, like the class of a method's global.
bool RizinPrintCSharp::isMetadata(const Datatype *ct) const
{
	if(ct->getMetatype() != TYPE_PTR)
		return false;
	const RzGhidraCSharpType *type = findType(((const TypePointer *)ct)->getPtrTo());
	return type && type->is_metadata;
}

/// Returns whether a statement sets a class's metadata to what a function that the names don't know returns for it,
/// like `klass = InitFromCodegenSlow(klass)`, which runs the class's static constructor once and returns the class.
bool RizinPrintCSharp::isClassInit(const PcodeOp *op) const
{
	const Varnode *out = op->getOut();
	if(!out || !isMetadata(out->getHigh()->getType()))
		return false;
	while(op->code() == CPUI_CAST && op->getIn(0)->isWritten())
		op = op->getIn(0)->getDef();

	Function callee;
	unsigned int sharer;
	if(op->code() != CPUI_CALL || op->numInput() != 2 || findCallee(op, callee) || findSharer(op, callee, sharer))
		return false;
	const Varnode *klass = op->getIn(1);
	while(klass->isImplied() && klass->isWritten() && klass->getDef()->code() == CPUI_CAST)
		klass = klass->getDef()->getIn(0);
	return klass->getHigh() == out->getHigh();
}

/// Returns whether the body of an `if` only runs a class's static constructor or fills metadata globals and sets
/// the flag that it did.
bool RizinPrintCSharp::isRuntimeCheck(const FlowBlock *body) const
{
	while(body->getType() == FlowBlock::t_copy)
		body = body->subBlock(0);
	if(body->getType() != FlowBlock::t_basic)
		return false;

	const BlockBasic *basic = (const BlockBasic *)body;
	bool hasHelper = false;
	bool hasFlag = false;
	bool hasCallByNumber = false;
	for(auto it = basic->beginOp(); it != basic->endOp(); ++it)
	{
		const PcodeOp *op = *it;
		const Varnode *out = op->getOut();
		if(op->notPrinted() || op->isBranch() || (out && out->isImplied()))
			continue;

		Function callee;
		bool isHelper = findCallee(op, callee) && (callee.kind == RZ_GHIDRA_CSHARP_CLASS_INIT || callee.kind == RZ_GHIDRA_CSHARP_METADATA_INIT);
		isHelper = isHelper || isClassInit(op);
		bool isFlag = isFlagStore(op);
		bool isByNumber = !isHelper && isCallByNumber(op);
		if(!isHelper && !isFlag && !isByNumber)
			return false;
		hasHelper = hasHelper || isHelper;
		hasFlag = hasFlag || isFlag;
		hasCallByNumber = hasCallByNumber || isByNumber;
	}
	// A call by a number only fills metadata when the body sets the flag that it did
	return hasHelper || (hasCallByNumber && hasFlag);
}

/// Returns whether a branch skips the body of an `if` that only does the runtime's checks, which don't print.
bool RizinPrintCSharp::isRuntimeBranch(const PcodeOp *op) const
{
	const FlowBlock *condition = op->getParent();
	if(condition->sizeOut() != 2)
		return false;
	for(int4 i = 0; i < 2; ++i)
	{
		const FlowBlock *body = condition->getOut(i);
		bool isSkipped = body->sizeIn() == 1 && body->sizeOut() == 1 && body->getOut(0) == condition->getOut(1 - i);
		if(isSkipped && isRuntimeCheck(body))
			return true;
	}
	return false;
}

/// Returns whether a read of a class's metadata doesn't show in the printed code: it finds the class's static fields,
/// which print as `Class.field`, it sets a variable of metadata, it tests the class's flags in a runtime check or it
/// passes the class to the function of a runtime check.
bool RizinPrintCSharp::isSilentRead(const PcodeOp *op, int depth) const
{
	if(depth > 8)
		return false;
	if(op->code() == CPUI_CBRANCH)
		return isRuntimeBranch(op);
	if(isHiddenStatement(op))
		return true;

	const Varnode *out = op->getOut();
	if(!out)
		return false;
	if(!out->isImplied())
		return isMetadata(out->getHigh()->getType()) || isClassInit(op);

	const Datatype *ct = out->getHighTypeDefFacing();
	const Datatype *pointed = ct->getMetatype() == TYPE_PTR ? ((const TypePointer *)ct)->getPtrTo() : nullptr;
	const RzGhidraCSharpType *type = pointed ? findType(pointed) : nullptr;
	if(type && type->is_static)
		return true;
	for(auto it = out->beginDescend(); it != out->endDescend(); ++it)
	{
		if(!isSilentRead(*it, depth + 1))
			return false;
	}
	return true;
}

/// Returns whether a variable of a class's metadata stays out of the printed code with its statements, because C#
/// doesn't have a form for it and no printed statement reads it.
bool RizinPrintCSharp::isHiddenMetadata(const HighVariable *high) const
{
	if(!isMetadata(high->getType()))
		return false;
	for(int4 i = 0; i < high->numInstances(); ++i)
	{
		const Varnode *vn = high->getInstance(i);
		for(auto it = vn->beginDescend(); it != vn->endDescend(); ++it)
		{
			if(!isSilentRead(*it, 0))
				return false;
		}
	}
	return true;
}

void RizinPrintCSharp::emitVarDeclStatement(const Symbol *sym)
{
	// leaves out the declaration of a symbol whose variables all stay out of the printed code
	if(!printed)
	{
		RizinPrintC::emitVarDeclStatement(sym);
		return;
	}

	bool isHidden = false;
	for(auto it = printed->beginLoc(); it != printed->endLoc(); ++it)
	{
		// a free variable, like a constant, doesn't have a high variable
		if((*it)->isFree())
			continue;
		const HighVariable *high = (*it)->getHigh();
		if(high->getSymbol() != sym)
			continue;
		if(!isHiddenMetadata(high))
		{
			isHidden = false;
			break;
		}
		isHidden = true;
	}
	if(!isHidden)
		RizinPrintC::emitVarDeclStatement(sym);
}

void RizinPrintCSharp::emitBlockIf(const BlockIf *bl)
{
	bool isPlain = !isSet(pending_brace) && bl->getSize() == 2 && bl->getGotoTarget() == (FlowBlock *)0;
	if(!isPlain || !isRuntimeCheck(bl->getBlock(1)))
	{
		RizinPrintC::emitBlockIf(bl);
		return;
	}

	// The statements before the condition still print
	pushMod();
	unsetMod(no_branch | only_branch | pending_brace);
	setMod(no_branch);
	bl->getBlock(0)->emit(this);
	popMod();
}

// PrintC::emitBlockBasic without the statements that C# doesn't have a form for
void RizinPrintCSharp::emitBlockBasic(const BlockBasic *bb)
{
	if(isSet(only_branch))
	{
		RizinPrintC::emitBlockBasic(bb);
		return;
	}

	commsorter.setupBlockList(bb);
	emitLabelStatement(bb);
	bool separator = false;
	for(auto iter = bb->beginOp(); iter != bb->endOp(); ++iter)
	{
		const PcodeOp *inst = *iter;
		if(inst->notPrinted())
			continue;
		if(inst->isBranch() && (isSet(no_branch) || inst->code() == CPUI_BRANCH))
			continue;
		const Varnode *vn = inst->getOut();
		if(vn != (const Varnode *)0 && vn->isImplied())
			continue;
		if(isHiddenStatement(inst) || (vn && isHiddenMetadata(vn->getHigh())))
			continue;
		if(separator && isSet(comma_separate))
		{
			emit->print(COMMA);
			emit->spaces(1);
		}
		else if(!isSet(comma_separate))
		{
			emitCommentGroup(inst);
			emit->tagLine();
		}
		emitStatement(inst);
		separator = true;
	}
	if(isSet(flat) && isSet(nofallthru))
	{
		const PcodeOp *inst = bb->lastOp();
		emit->tagLine();
		int4 id = emit->beginStatement(inst);
		emit->print(KEYWORD_GOTO, EmitMarkup::keyword_color);
		emit->spaces(1);
		if(bb->sizeOut() == 2)
			emitLabel(bb->getOut(inst->isFallthruTrue() ? 1 : 0));
		else
			emitLabel(bb->getOut(0));
		emit->print(SEMICOLON);
		emit->endStatement(id);
	}
	emitCommentGroup((const PcodeOp *)0);
}

/// Pushes the name of a called function's type, as a token of the generic method's instance that names the type,
/// or of the call.
void RizinPrintCSharp::pushTypeOf(const PcodeOp *op, const Function &callee)
{
	if(callee.instance)
		pushAtom(Atom(callee.type, vartoken, EmitMarkup::type_color, op, callee.instance));
	else
		pushAtom(Atom(callee.type, optoken, EmitMarkup::type_color, op));
}

void RizinPrintCSharp::pushReceiver(const PcodeOp *op, const Function &callee)
{
	if(callee.isStatic)
	{
		pushTypeOf(op, callee);
		return;
	}

	const Varnode *receiver = op->getIn(1);
	if(!isThis(receiver, op))
	{
		pushVn(receiver, op, mods);
		return;
	}

	// A call of the same member of another class on the method's own object is the call of the base class's member
	Function current;
	findFunction(op->getParent()->getFuncdata()->getAddress(), current);
	bool isBase = current.type != callee.type && current.name == callee.name;
	pushAtom(Atom(isBase ? KEYWORD_BASE : KEYWORD_THIS, syntax, EmitMarkup::keyword_color));
}

/// Pushes a member's name after its receiver, and remembers the call of an accessor whose name is its property's,
/// so the code's parser can link the property.
void RizinPrintCSharp::pushMember(const PcodeOp *op, const Function &callee, bool isProperty)
{
	if(isProperty && !callee.isFromInstance)
		propertyCalls.insert(op->getTime());
	// A static function without a type is code that several methods share, which doesn't belong to 1 class
	if(!callee.isStatic || !callee.type.empty())
	{
		// The same operator as a field of an object, so a member of a member doesn't get parentheses
		pushOp(callee.isStatic ? &object_member : &pointer_member, op);
		pushReceiver(op, callee);
	}
	if(callee.isFromInstance)
		pushAtom(Atom(callee.name, vartoken, EmitMarkup::funcname_color, op, callee.instance));
	else
		pushAtom(Atom(callee.name, functoken, EmitMarkup::funcname_color, op, (const Funcdata *)0));
}

void RizinPrintCSharp::pushArguments(const PcodeOp *op, int first, int count)
{
	if(count == 0)
	{
		pushAtom(Atom(EMPTY_STRING, blanktoken, EmitMarkup::no_color));
		return;
	}
	for(int i = 0; i < count - 1; ++i)
		pushOp(&comma, op);
	// Implied varnodes are pushed in reverse order, see PrintLanguage::pushVnImplied
	for(int i = first + count - 1; i >= first; --i)
		pushVn(op->getIn(i), op, mods);
}

bool RizinPrintCSharp::pushOperator(const PcodeOp *op, const Function &callee, int first)
{
	static const std::map<std::string, OpToken *> unary = {
		{ "-", &unary_minus }, { "+", &unary_plus }, { "!", &boolean_not }, { "~", &bitwise_not },
	};
	static const std::map<std::string, OpToken *> binary = {
		{ "+", &binary_plus }, { "-", &binary_minus }, { "*", &multiply }, { "/", &divide }, { "%", &modulo },
		{ "&", &bitwise_and }, { "|", &bitwise_or }, { "^", &bitwise_xor }, { "<<", &shift_left }, { ">>", &shift_right },
		{ "==", &equal }, { "!=", &not_equal }, { "<", &less_than }, { ">", &greater_than },
		{ "<=", &less_equal }, { ">=", &greater_equal },
	};
	const auto &tokens = callee.parameters == 1 ? unary : binary;
	auto found = tokens.find(callee.name);
	if(found == tokens.end() || callee.parameters < 1 || callee.parameters > 2)
		return false;

	pushOp(found->second, op);
	for(int i = first + callee.parameters - 1; i >= first; --i)
		pushVn(op->getIn(i), op, mods);
	return true;
}

void RizinPrintCSharp::pushRaise(const PcodeOp *op, const Function &callee)
{
	if(callee.type.empty() && op->numInput() < 2)
	{
		RizinPrintC::opCall(op);
		return;
	}

	pushOp(&throw_op, op);
	pushAtom(Atom(KEYWORD_THROW, syntax, EmitMarkup::keyword_color));
	if(callee.type.empty())
	{
		pushVn(op->getIn(1), op, mods);
		return;
	}

	pushOp(&new_op, op);
	pushAtom(Atom(KEYWORD_NEW, syntax, EmitMarkup::keyword_color));
	pushOp(&function_call, op);
	// A token of the call, so the code's parser links the exception's class like a called function's declaring type
	pushAtom(Atom(callee.type, optoken, EmitMarkup::type_color, op));
	pushAtom(Atom(EMPTY_STRING, blanktoken, EmitMarkup::no_color));
}

/// Pushes a constructor's call without an allocation on the method's own object as `base(...)` or `this(...)`, and any
/// other such call like C does, because C# doesn't have a form for it.
void RizinPrintCSharp::pushConstructorChain(const PcodeOp *op, const Function &callee, int first)
{
	if(!isThis(op->getIn(1), op))
	{
		RizinPrintC::opCall(op);
		return;
	}

	Function current;
	findFunction(op->getParent()->getFuncdata()->getAddress(), current);
	pushOp(&function_call, op);
	pushAtom(Atom(current.type == callee.type ? KEYWORD_THIS : KEYWORD_BASE, syntax, EmitMarkup::keyword_color));
	pushArguments(op, first, callee.parameters);
}

void RizinPrintCSharp::opCall(const PcodeOp *op)
{
	Function callee;
	bool isKnown = findCallee(op, callee);

	// The hidden last argument of a generic method's call is the global of the method's instance, which has the
	// type's arguments, and the method itself when the call's target is code that the names don't know
	Global instance;
	const Varnode *last = op->numInput() > 1 ? op->getIn(op->numInput() - 1) : nullptr;
	bool hasInstance = last && findGlobal(last, instance) && instance.hasMethod;

	// A call of code that several methods share reads as one of those methods, unless the hidden argument names one
	unsigned int sharer;
	Function shared;
	if(!hasInstance && findSharer(op, shared, sharer))
	{
		callee = shared;
		isKnown = true;
		sharerCalls[op->getTime()] = sharer;
	}

	if(hasInstance && (!isKnown || callee.kind <= RZ_GHIDRA_CSHARP_OPERATOR))
	{
		if(!isKnown)
		{
			callee = instance.method;
			callee.isFromInstance = true;
		}
		if(!instance.type.empty())
			callee.type = instance.type;
		callee.instance = last;
		isKnown = true;
	}
	if(!isKnown)
	{
		RizinPrintC::opCall(op);
		return;
	}
	if(callee.kind == RZ_GHIDRA_CSHARP_RAISE)
	{
		pushRaise(op, callee);
		return;
	}

	// The call has the object first, unless the method is static, and a hidden argument for the method last
	int count = op->numInput() - 1;
	int first = callee.isStatic ? 1 : 2;
	if(callee.kind > RZ_GHIDRA_CSHARP_OPERATOR || count != callee.parameters + first)
	{
		RizinPrintC::opCall(op);
		return;
	}

	switch(callee.kind)
	{
		case RZ_GHIDRA_CSHARP_OPERATOR:
			if(pushOperator(op, callee, first))
				return;
			break;
		case RZ_GHIDRA_CSHARP_GETTER:
			if(callee.parameters == 0)
			{
				pushMember(op, callee, true);
				return;
			}
			pushOp(&subscript, op);
			pushReceiver(op, callee);
			pushArguments(op, first, callee.parameters);
			return;
		case RZ_GHIDRA_CSHARP_SETTER:
			if(callee.parameters < 1)
				break;
			pushOp(&assignment, op);
			if(callee.parameters == 1)
				pushMember(op, callee, true);
			else
			{
				pushOp(&subscript, op);
				pushReceiver(op, callee);
				pushArguments(op, first, callee.parameters - 1);
			}
			pushVn(op->getIn(first + callee.parameters - 1), op, mods);
			return;
		case RZ_GHIDRA_CSHARP_CONSTRUCTOR:
		{
			const PcodeOp *allocation = callee.isStatic ? nullptr : findAllocation(op);
			if(!allocation)
			{
				pushConstructorChain(op, callee, first);
				return;
			}
			pushOp(&assignment, op);
			pushSymbolDetail(allocation->getOut(), op, false);
			// The allocation's class has the type's arguments, which the constructor of a generic type doesn't
			Global allocated;
			if(allocation->numInput() > 1 && findGlobal(allocation->getIn(1), allocated) && !allocated.type.empty())
			{
				callee.type = allocated.type;
				callee.instance = allocation->getIn(1);
			}
			pushOp(&new_op, op);
			pushAtom(Atom(KEYWORD_NEW, syntax, EmitMarkup::keyword_color));
			pushOp(&function_call, op);
			pushTypeOf(op, callee);
			pushArguments(op, first, callee.parameters);
			return;
		}
		default:
			break;
	}

	pushOp(&function_call, op);
	pushMember(op, callee);
	pushArguments(op, first, callee.parameters);
}

/// Pushes the array itself for the member with the items of an array's object, so an item reads as `array[index]`,
/// and returns false for another member.
bool RizinPrintCSharp::pushItems(const PcodeOp *op, const TypePointer *pointer)
{
	int8 offset = AddrSpace::addressToByteInt((int4)op->getIn(1)->getOffset(), pointer->getWordSize());
	int8 inField = 0;
	const TypeField *field = ((const TypeStruct *)pointer->getPtrTo())->findTruncation(offset, 0, op, 0, inField);
	if(!field || inField != 0 || field->type->getMetatype() != TYPE_ARRAY)
		return false;

	// The first item, when nothing adds an index to the items' address
	bool isValue = (mods & (print_load_value | print_store_value)) != 0;
	uint4 m = mods & ~(print_load_value | print_store_value);
	if(isValue)
		pushOp(&subscript, op);
	pushVn(op->getIn(0), op, m);
	if(isValue)
		push_integer(0, 4, false, syntax, (Varnode *)0, op, 0);
	return true;
}

void RizinPrintCSharp::opPtrsub(const PcodeOp *op)
{
	const Varnode *in0 = op->getIn(0);
	const Datatype *pointer = in0->getHighTypeReadFacing(op);
	const Datatype *ct = pointer->getMetatype() == TYPE_PTR ? ((const TypePointer *)pointer)->getPtrTo() : nullptr;
	const RzGhidraCSharpType *type = ct ? findType(ct) : nullptr;
	if(type && type->is_array && pushItems(op, (const TypePointer *)pointer))
		return;
	if(!type || !type->is_static)
	{
		RizinPrintC::opPtrsub(op);
		return;
	}

	// A member of a class's static fields is `Class.field`, whatever expression finds the fields' memory
	int8 offset = AddrSpace::addressToByteInt((int4)op->getIn(1)->getOffset(), ((const TypePointer *)pointer)->getWordSize());
	int8 inField = 0;
	const TypeField *field = ((const TypeStruct *)ct)->findTruncation(offset, 0, op, 0, inField);
	if(!field || inField != 0)
	{
		RizinPrintC::opPtrsub(op);
		return;
	}

	bool isArray = field->type->getMetatype() == TYPE_ARRAY;
	bool isValue = (mods & (print_load_value | print_store_value)) != 0;
	std::string name = typeName(ct);
	if(!isValue && !isArray)
		pushOp(&addressof, op);
	else if(isValue && isArray)
		pushOp(&subscript, op);
	pushOp(&object_member, op);
	pushAtom(Atom(name, typetoken, EmitMarkup::type_color, ct));
	pushAtom(Atom(field->name, fieldtoken, EmitMarkup::no_color, ct, field->ident, op));
	if(isValue && isArray)
		push_integer(0, 4, false, syntax, (Varnode *)0, op, 0);
}
