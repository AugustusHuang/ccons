#ifndef CCONS_PARSER_H
#define CCONS_PARSER_H

//
// Parser is used to invoke the clang libraries to perform actual parsing of
// the input received in the Console.
//
// Part of ccons, the interactive console for the C programming language.
//
// Copyright (c) 2009 Alexei Svitkine. This file is distributed under the
// terms of MIT Open Source License. See file LICENSE for details.
//

#include <string>
#include <vector>

// #include <llvm/ADT/OwningPtr.h>
// OwningPtr<T> replaced by std::unique_ptr<T>.
#include <llvm/Support/MemoryBuffer.h>

#include <clang/Basic/FileManager.h>
#include <clang/Basic/LangOptions.h>
#include <clang/Basic/TargetOptions.h>
#include <clang/Lex/HeaderSearchOptions.h>
#include <clang/Lex/PreprocessorOptions.h>
#include <clang/Lex/HeaderSearch.h>
#include <clang/Lex/ModuleLoader.h>
// In order to get definition of GlobalModuleIndex.
#include <clang/Serialization/GlobalModuleIndex.h>

namespace clang {
	class ASTConsumer;
	class ASTContext;
	class DiagnosticsEngine;
	class FileSystemOptions;
	class FunctionDecl;
	class Preprocessor;
	class PPCallbacks;
	class SourceManager;
	class TargetInfo;
	class Token;
} // namespace clang


namespace ccons {

//
// ParseOperation
// 

class ParseOperation : public clang::ModuleLoader {

public:
	
	ParseOperation(const clang::LangOptions& options,
	               clang::TargetOptions *targetOptions,
	               clang::DiagnosticsEngine *engine,
	               clang::PPCallbacks *callbacks = 0);
	virtual ~ParseOperation();

	clang::ASTContext *getASTContext() const;
	clang::Preprocessor *getPreprocessor() const;
	clang::SourceManager *getSourceManager() const;
	clang::TargetInfo *getTargetInfo() const;

	clang::ModuleLoadResult loadModule(clang::SourceLocation ImportLoc,
	                                   clang::ModuleIdPath Path,
	                                   clang::Module::NameVisibilityKind Visibility,
                                       bool IsInclusionDirective) override {
		return clang::ModuleLoadResult();
	};

    void makeModuleVisible(clang::Module *Mod,
                           clang::Module::NameVisibilityKind Visibility,
                           clang::SourceLocation ImportLoc,
                           bool Complain) override {};

	clang::GlobalModuleIndex *loadGlobalModuleIndex(
			clang::SourceLocation TriggerLoc) {
		return nullptr;
	};

	bool lookupMissingImports(clang::StringRef Name,
			clang::SourceLocation TriggerLoc) {
		return 0;
	};

private:

	clang::LangOptions _langOpts;
	llvm::IntrusiveRefCntPtr<clang::HeaderSearchOptions> _hsOptions;
	llvm::IntrusiveRefCntPtr<clang::PreprocessorOptions> _ppOptions;
	std::unique_ptr<clang::FileSystemOptions> _fsOpts;
	std::unique_ptr<clang::FileManager> _fm;
	std::unique_ptr<clang::SourceManager> _sm;
	std::unique_ptr<clang::HeaderSearch> _hs;
	std::unique_ptr<clang::Preprocessor> _pp;
	std::unique_ptr<clang::ASTContext> _ast;
	std::unique_ptr<clang::TargetInfo> _target;

};


//
// Parser
// 

class Parser {

public:

	Parser(const clang::LangOptions& options, clang::TargetOptions *targetOptions);
	~Parser();

	enum InputType { Incomplete, TopLevel, Stmt }; 

  // Analyze the specified input to determine whether its complete or not.
	InputType analyzeInput(const std::string& contextSource,
	                       const std::string& buffer,
	                       int& indentLevel,
	                       std::vector<clang::FunctionDecl*> *fds);

	// Create a new ParseOperation that the caller should take ownership of
	// and the lifetime of which must be shorter than of the Parser.
	ParseOperation *createParseOperation(clang::DiagnosticsEngine *engine,
	                                      clang::PPCallbacks *callbacks = 0);

	// Parse the specified source code with the specified parse operation
	// and consumer. Upon parsing, ownership of parseOp is transferred to
	// the Parser permanently.
	void parse(const std::string& src,
	           ParseOperation *parseOp,
	           clang::ASTConsumer *consumer);

	// Parse by implicitely creating a ParseOperation. Equivalent to
	// parse(src, createParseOperation(diag), consumer).
	void parse(const std::string& src,
	           clang::DiagnosticsEngine *engine,
	           clang::ASTConsumer *consumer);

	// Returns the last parse operation or NULL if there isn't one.
	ParseOperation *getLastParseOperation() const;

	// Release any accumulated parse operations (including their resulting
	// ASTs and other clang data structures).
	void releaseAccumulatedParseOperations();

private:

	const clang::LangOptions& _options;
	clang::TargetOptions *_targetOptions;
	std::vector<ParseOperation*> _ops;

	int analyzeTokens(clang::Preprocessor& PP,
	                  const llvm::MemoryBuffer *MemBuf,
	                  clang::Token& LastTok,
	                  int& IndentLevel,
	                  bool& TokWasDo);

	static llvm::MemoryBuffer *createMemoryBuffer(const std::string& src,
	                                              const char *name,
	                                              clang::SourceManager *sm);

};

} // namespace ccons

#endif // CCONS_PARSER_H
