//
// Utility functionality for dealing with the clang libraries and
// manipulating clang data structures.
//
// Part of ccons, the interactive console for the C programming language.
//
// Copyright (c) 2009 Alexei Svitkine. This file is distributed under the
// terms of MIT Open Source License. See file LICENSE for details.
//

#include "ClangUtils.h"

#include <clang/AST/AST.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Lex/Lexer.h>
#include <clang/Lex/MacroInfo.h>
#include <clang/Lex/Preprocessor.h>
#include <clang/Sema/SemaDiagnostic.h>

namespace ccons {

SrcRange getStmtRange(const clang::Stmt *S,
                      const clang::SourceManager& sm,
                      const clang::LangOptions& options)
{
	clang::SourceLocation SLoc = sm.getInstantiationLoc(S->getLocStart());
	clang::SourceLocation ELoc = sm.getInstantiationLoc(S->getLocEnd());
	unsigned start = sm.getFileOffset(SLoc);
	unsigned end   = sm.getFileOffset(ELoc);
	end += clang::Lexer::MeasureTokenLength(ELoc, sm, options);
	return SrcRange(start, end);
}

SrcRange getStmtRangeWithSemicolon(const clang::Stmt *S,
                                   const clang::SourceManager& sm,
                                   const clang::LangOptions& options)
{
	clang::SourceLocation SLoc = sm.getInstantiationLoc(S->getLocStart());
	clang::SourceLocation ELoc = sm.getInstantiationLoc(S->getLocEnd());
	unsigned start = sm.getFileOffset(SLoc);
	unsigned end   = sm.getFileOffset(ELoc);

	// Below code copied from clang::Lexer::MeasureTokenLength():
	clang::SourceLocation Loc = sm.getInstantiationLoc(ELoc);
	std::pair<clang::FileID, unsigned> LocInfo = sm.getDecomposedLoc(Loc);
	std::pair<const char *,const char *> Buffer = sm.getBufferData(LocInfo.first);
	const char *StrData = Buffer.first+LocInfo.second;
	clang::Lexer TheLexer(Loc, options, Buffer.first, StrData, Buffer.second);
	clang::Token TheTok;
	TheLexer.LexFromRawLexer(TheTok);
	// End copied code.
	end += TheTok.getLength();

	// Check if we the source range did include the semicolon.
	if (TheTok.isNot(clang::tok::semi) && TheTok.isNot(clang::tok::r_brace)) {
		TheLexer.LexFromRawLexer(TheTok);
		if (TheTok.is(clang::tok::semi)) {
			end += TheTok.getLength();
		}
	}

	return SrcRange(start, end);
}

SrcRange getMacroRange(const clang::MacroInfo *MI,
                       const clang::SourceManager& sm,
                       const clang::LangOptions& options)
{
	clang::SourceLocation SLoc = sm.getInstantiationLoc(MI->getDefinitionLoc());
	clang::SourceLocation ELoc = sm.getInstantiationLoc(MI->getDefinitionEndLoc());
	unsigned start = sm.getFileOffset(SLoc);
	unsigned end   = sm.getFileOffset(ELoc);
	end += clang::Lexer::MeasureTokenLength(ELoc, sm, options);
	return SrcRange(start, end);

}

} // namespace ccons