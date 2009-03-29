#ifndef CCONS_PARSER_H
#define CCONS_PARSER_H

#include <string>

#include <llvm/ADT/OwningPtr.h>
#include <llvm/Support/MemoryBuffer.h>

#include <clang/Basic/LangOptions.h>
#include <clang/Basic/FileManager.h>

namespace clang {
	class ASTConsumer;
	class ASTContext;
	class Diagnostic;
	class FunctionDecl;
	class Preprocessor;
	class SourceManager;
	class TargetInfo;
} // namespace clang


namespace ccons {

class Parser {

public:

	explicit Parser(const clang::LangOptions& options);

	enum InputType { Incomplete, TopLevel, Stmt }; 

	InputType analyzeInput(const std::string& contextSource,
	                       const std::string& buffer,
	                       int& indentLevel,
	                       const clang::FunctionDecl*& FD);
	void parse(const std::string& source,
						 clang::SourceManager *sm,
	           clang::Diagnostic *diag,
	           clang::ASTConsumer *consumer);

  clang::ASTContext * getContext() const;

private:

	const clang::LangOptions& _options;
	clang::FileManager _fm;
	llvm::OwningPtr<clang::TargetInfo> _target;
	llvm::OwningPtr<clang::Preprocessor> _pp;
	llvm::OwningPtr<clang::ASTContext> _ast;

	static llvm::MemoryBuffer * createMemoryBuffer(const std::string& src,
	                                               const char *name,
	                                               clang::SourceManager *sm);

};

} // namespace ccons

#endif // CCONS_PARSER_H