// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_H
#define RZ_GHIDRA_H

#include <rz_util/rz_annotated_code.h>
#include <rz_core.h>

#if __cplusplus
extern "C" {
#endif

RZ_API RzAnnotatedCode *rz_ghidra_decompile_annotated_code(RzCore *core, ut64 addr);

/**
 * \brief What a function of a C# program is, which decides how the C# printer writes its calls.
 */
typedef enum {
	RZ_GHIDRA_CSHARP_METHOD, ///< a method, called as `receiver.Name(arguments)` or `Type.Name(arguments)`
	RZ_GHIDRA_CSHARP_GETTER, ///< a property's getter, `receiver.Name`, or an indexer's with parameters, `receiver[index]`
	RZ_GHIDRA_CSHARP_SETTER, ///< a property's or indexer's setter, `receiver.Name = value`
	RZ_GHIDRA_CSHARP_CONSTRUCTOR, ///< a constructor, `new Type(arguments)` after the object's allocation
	RZ_GHIDRA_CSHARP_OPERATOR, ///< an operator whose name is its token, like `==`
	RZ_GHIDRA_CSHARP_CLASS_INIT, ///< the runtime's function that runs a class's static constructor
	RZ_GHIDRA_CSHARP_OBJECT_NEW, ///< the runtime's function that allocates an object of a class
	RZ_GHIDRA_CSHARP_WRITE_BARRIER, ///< the runtime's function that tells the garbage collector about a stored reference
	RZ_GHIDRA_CSHARP_RAISE, ///< a function of the runtime that raises an exception, of the class `type` when it has one
	RZ_GHIDRA_CSHARP_METADATA_INIT, ///< the runtime's function that fills a global with its piece of metadata
} RzGhidraCSharpKind;

/**
 * \brief A function as C# knows it. The texts only have to live until the next call of the names' callbacks.
 */
typedef struct rz_ghidra_csharp_function_t {
	RzGhidraCSharpKind kind;
	const char *type; ///< the C# name of the declaring type, like `List<int>`
	const char *name; ///< the member's name, or the operator's token
	bool is_static;
	ut32 parameters; ///< the count of the C# parameters, without `this` and without a hidden last parameter
} RzGhidraCSharpFunction;

/**
 * \brief A struct as C# knows it.
 */
typedef struct rz_ghidra_csharp_type_t {
	const char *name; ///< the C# name of the struct's type, like `Circle`
	bool is_object; ///< whether a pointer to the struct is a reference to an object of the class
	bool is_static; ///< whether the struct has the static fields of the class
	bool is_array; ///< whether the struct is an array's object, whose member of an array type has the array's items
} RzGhidraCSharpType;

/**
 * \brief A global as C# knows it, like the global that a runtime fills with a class or a method.
 */
typedef struct rz_ghidra_csharp_global_t {
	const char *text; ///< the C# text of the global, like `typeof(Circle)`
	const char *type; ///< the C# name of a class's global or of the declaring type of a method's global, or NULL
	const RzGhidraCSharpFunction *method; ///< the method of a method's global, or NULL
} RzGhidraCSharpGlobal;

/**
 * \brief The names that the C# printer asks for while it prints a function.
 */
typedef struct rz_ghidra_csharp_names_t {
	void *user;
	/// Returns the function at an address, or NULL for a function that C# doesn't know.
	const RzGhidraCSharpFunction *(*function)(void *user, ut64 addr);
	/// Returns the global at an address, or NULL for a global that C# doesn't know.
	const RzGhidraCSharpGlobal *(*global)(void *user, ut64 addr);
	/// Returns the struct with a name, or NULL for a struct that C# doesn't know.
	const RzGhidraCSharpType *(*type)(void *user, const char *name);
} RzGhidraCSharpNames;

typedef enum {
	RZ_GHIDRA_CSHARP_LINK_TYPE, ///< the name of the type of the struct `name`
	RZ_GHIDRA_CSHARP_LINK_FIELD, ///< the name of the member at `offset` of the struct `name`
	RZ_GHIDRA_CSHARP_LINK_DECLARING_TYPE, ///< the name of the declaring type of the function at `offset`
	RZ_GHIDRA_CSHARP_LINK_PROPERTY, ///< the name of the property of the accessor at `offset`
} RzGhidraCSharpLinkKind;

/**
 * \brief A part of the C# that names a type, a field or a property, which Rizin's annotations don't have a type for.
 */
typedef struct rz_ghidra_csharp_link_t {
	size_t start;
	size_t end;
	RzGhidraCSharpLinkKind kind;
	char *name; ///< the struct's name, which the caller frees
	ut64 offset;
} RzGhidraCSharpLink;

/**
 * \brief Decompiles the function at an address and prints it the way C# writes the code, with the given names.
 *
 * Adds the parts that name types, fields and properties to `links`, a vector of RzGhidraCSharpLink.
 */
RZ_API RzAnnotatedCode *rz_ghidra_decompile_csharp(RzCore *core, ut64 addr, const RzGhidraCSharpNames *names, RzVector /*<RzGhidraCSharpLink>*/ *links);

#if __cplusplus
}
#endif

#endif //RZ_GHIDRA_H
