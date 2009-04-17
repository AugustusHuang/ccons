#include "Parser.h"

#include <iostream>
#include <stack>
#include <algorithm>

#include <llvm/Config/config.h>

#include <clang/AST/ASTConsumer.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/Frontend/InitHeaderSearch.h>
#include <clang/Lex/HeaderSearch.h>
#include <clang/Lex/Preprocessor.h>
#include <clang/Sema/ParseAST.h>
#include <clang/Sema/SemaDiagnostic.h>

#include <clang/Basic/TargetInfo.h>
#include <clang/Basic/Diagnostic.h>

#include "ClangUtils.h"
#include "SrcGen.h"

// Temporary Hax:
#include "InitPP.cpp"

using std::string;

namespace ccons {


//
// ParseOperation
//

ParseOperation::ParseOperation(const clang::LangOptions& options,
                               clang::TargetInfo& target,
                               clang::Diagnostic *diag,
                               clang::SourceManager *sm) :
	_sm(sm),
	_fm(new clang::FileManager),
	_hs(new clang::HeaderSearch(*_fm))
{
	if (!sm)
		_sm.reset(new clang::SourceManager);
	clang::InitHeaderSearch ihs(*_hs);
	ihs.AddDefaultEnvVarPaths(options);
	ihs.AddDefaultSystemIncludePaths(options);
	ihs.Realize();
	_pp.reset(new clang::Preprocessor(*diag, options, target, *_sm, *_hs));
	InitializePreprocessor(*_pp);
	_ast.reset(new clang::ASTContext(options, *_sm, target,
		_pp->getIdentifierTable(), _pp->getSelectorTable()));
}

clang::ASTContext * ParseOperation::getASTContext() const
{
	return _ast.get();
}

clang::Preprocessor * ParseOperation::getPreprocessor() const
{
	return _pp.get();
}

clang::SourceManager * ParseOperation::getSourceManager() const
{
	return _sm.get();
}


//
// Parser
//

Parser::Parser(const clang::LangOptions& options) :
	_options(options),
	_target(clang::TargetInfo::CreateTargetInfo(LLVM_HOSTTRIPLE))
{
}

Parser::~Parser()
{
	releaseAccumulatedParseOperations();
}

void Parser::releaseAccumulatedParseOperations()
{
	for (std::vector<ParseOperation*>::iterator I = _ops.begin(), E = _ops.end();
	     I != E; ++I) {
		delete *I;
	}
	_ops.clear();
}


ParseOperation * Parser::getLastParseOperation() const
{
	return _ops.back();
}

Parser::InputType Parser::analyzeInput(const string& contextSource,
                                       const string& buffer,
                                       int& indentLevel,
                                       const clang::FunctionDecl*& FD)
{
	if (buffer.length() > 1 && buffer[buffer.length() - 2] == '\\') {
		indentLevel = 1;
		return Incomplete;
	}
	
	ProxyDiagnosticClient pdc(NULL);
	clang::Diagnostic diag(&pdc);
	llvm::OwningPtr<ParseOperation>
		parseOp(new ParseOperation(_options, *_target, &diag));
	createMemoryBuffer(buffer, "", parseOp->getSourceManager());

	clang::Token LastTok;
	bool TokWasDo = false;
	unsigned stackSize =
		analyzeTokens(*parseOp->getPreprocessor(), LastTok, indentLevel, TokWasDo);

	// TokWasDo is used for do { ... } while (...); loops
	if (LastTok.is(clang::tok::semi) || (LastTok.is(clang::tok::r_brace) && !TokWasDo)) {
		if (stackSize > 0) return Incomplete;
		ProxyDiagnosticClient pdc(NULL); // do not output diagnostics
		clang::Diagnostic diag(&pdc);
		// Setting this ensures "foo();" is not a valid top-level declaration.
		diag.setDiagnosticMapping(clang::diag::warn_missing_type_specifier,
	                            clang::diag::MAP_ERROR);
		diag.setSuppressSystemWarnings(true);
		string src = contextSource + buffer;
		struct : public clang::ASTConsumer {
			unsigned pos;
			unsigned maxPos;
			clang::SourceManager *sm;
			clang::FunctionDecl *FD;
			void HandleTopLevelDecl(clang::DeclGroupRef D) {
				for (clang::DeclGroupRef::iterator I = D.begin(), E = D.end(); I != E; ++I) {
					if (clang::FunctionDecl *FuD = dyn_cast<clang::FunctionDecl>(*I)) {
						clang::SourceLocation Loc = FuD->getTypeSpecStartLoc();
						unsigned offset = sm->getFileOffset(sm->getInstantiationLoc(Loc));
						if (offset == pos) {
							this->FD = FuD;
						}
					}
				}
			}
		} consumer;
		consumer.pos = contextSource.length();
		consumer.maxPos = consumer.pos + buffer.length();
		consumer.sm = new clang::SourceManager;
		consumer.FD = NULL;
		parse(src, &diag, &consumer, consumer.sm);
		if (!pdc.hadErrors() && consumer.FD) {
			FD = consumer.FD;
			return TopLevel;
		}
		return Stmt;
	}

	return Incomplete;
}

unsigned Parser::analyzeTokens(clang::Preprocessor& PP,
                               clang::Token& LastTok,
                               int& indentLevel,
                               bool& TokWasDo)
{
	std::stack<std::pair<clang::Token, clang::Token> > S; // Tok, PrevTok

	indentLevel = 0;
	PP.EnterMainSourceFile();

	clang::Token Tok;
	PP.Lex(Tok);
	while (Tok.isNot(clang::tok::eof)) {
		if (Tok.is(clang::tok::l_square)) {
			S.push(std::make_pair(Tok, LastTok)); // [
		} else if (Tok.is(clang::tok::l_paren)) {
			S.push(std::make_pair(Tok, LastTok)); // (
		} else if (Tok.is(clang::tok::l_brace)) {
			S.push(std::make_pair(Tok, LastTok)); // {
			indentLevel++;
		} else if (Tok.is(clang::tok::r_square)) {
			if (S.empty() || S.top().first.isNot(clang::tok::l_square)) {
				std::cout << "Unmatched [\n";
				return Incomplete;
			}
			TokWasDo = false;
			S.pop();
		} else if (Tok.is(clang::tok::r_paren)) {
			if (S.empty() || S.top().first.isNot(clang::tok::l_paren)) {
				std::cout << "Unmatched (\n";
				return Incomplete;
			}
			TokWasDo = false;
			S.pop();
		} else if (Tok.is(clang::tok::r_brace)) {
			if (S.empty() || S.top().first.isNot(clang::tok::l_brace)) {
				std::cout << "Unmatched {\n";
				return Incomplete;
			}
			TokWasDo = S.top().second.is(clang::tok::kw_do);
			S.pop();
			indentLevel--;
		}
		LastTok = Tok;
		PP.Lex(Tok);
	}

	// TODO: We need to properly account for indent-level for blocks that do not
	//       have braces... such as:
	//
	//       if (X)
	//         Y;
	//
	// TODO: Do-while without braces doesn't work, e.g.:
	//
	//       do
	//         foo();
	//       while (bar());
	//
	// Both of the above could be solved by some kind of rewriter-pass that would
	// insert implicit braces (or simply a more involved analysis).

	return S.size();
}

void Parser::parse(const string& src,
                   clang::Diagnostic *diag,
                   clang::ASTConsumer *consumer,
                   clang::SourceManager *sm)
{
	_ops.push_back(new ParseOperation(_options, *_target, diag, sm));
	createMemoryBuffer(src, "", _ops.back()->getSourceManager());
	clang::ParseAST(*_ops.back()->getPreprocessor(), consumer,
	                *_ops.back()->getASTContext());
}

llvm::MemoryBuffer * Parser::createMemoryBuffer(const string& src,
                                                const char *name,
                                                clang::SourceManager *sm)
{
	llvm::MemoryBuffer *mb =
		llvm::MemoryBuffer::getMemBufferCopy(&*src.begin(), &*src.end(), name);
	assert(mb && "Error creating MemoryBuffer!");
	sm->createMainFileIDForMemBuffer(mb);
	assert(!sm->getMainFileID().isInvalid() && "Error creating MainFileID!");
	return mb;
}

} // namespace ccons
