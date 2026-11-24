// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_CODEXMLPARSE_H
#define RZ_GHIDRA_CODEXMLPARSE_H

#include <rz_util/rz_annotated_code.h>
#include <rz_vector.h>

#include <map>
#include <string>

namespace ghidra {
class Funcdata;
};

/// The struct names by the ids of the types that C# code names, and the vector of RzGhidraCSharpLink that takes the
/// parts of the code that name types and fields
struct CodeXMLLinks
{
	const std::map<unsigned long long, std::string> *typeNames;
	RzVector *links;
};

RZ_API RzAnnotatedCode *ParseCodeXML(ghidra::Funcdata *func, const char *xml, const CodeXMLLinks *links = nullptr);

#endif //RZ_GHIDRA_CODEXMLPARSE_H
