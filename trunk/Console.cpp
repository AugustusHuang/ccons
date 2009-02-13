#include "Console.h"

#include <iostream>
#include <map>
#include <vector>
#include <sstream>

#include <llvm/ADT/OwningPtr.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Linker.h>
#include <llvm/Module.h>
#include <llvm/ModuleProvider.h>
#include <llvm/DerivedTypes.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/GenericValue.h>

#include <clang/AST/AST.h>
#include <clang/Basic/LangOptions.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/Basic/Diagnostic.h>
#include <clang/Driver/CompileOptions.h>
#include <clang/Driver/TextDiagnosticPrinter.h>
#include <clang/CodeGen/ModuleBuilder.h>
#include <clang/Lex/Preprocessor.h>
#include <clang/Sema/SemaDiagnostic.h>

#include "Parser.h"
#include "SrcGen.h"
#include "ClangUtils.h"


template<typename T>
inline std::string to_string(const T& t)
{
	std::stringstream ss;
	ss << t;
	return ss.str();
}

using std::string;

namespace ccons {

class StmtFinder : public clang::StmtVisitor<StmtFinder> {
public:

	explicit StmtFinder(unsigned pos, const clang::SourceManager& sm) :
		_pos(pos), _sm(sm), _S(NULL) {}
	~StmtFinder() {}

	void VisitChildren(clang::Stmt *S) {
		for (clang::Stmt::child_iterator I = S->child_begin(), E = S->child_end();
		     I != E; ++I) {
			if (*I) {
				Visit(*I);
			}
		}
	}

	void VisitStmt(clang::Stmt *S) {
		clang::SourceLocation Loc = S->getLocStart();
		if (_sm.getFileOffset(_sm.getInstantiationLoc(Loc)) == _pos) {
			_S = S;
		}
	}

	clang::Stmt * getStmt() { return _S; }

private:

	unsigned _pos;
	const clang::SourceManager& _sm;
	clang::Stmt *_S;
};

class FunctionBodyConsumer : public clang::ASTConsumer {
public:

	explicit FunctionBodyConsumer(StmtFinder *SF) : SF(SF) {}
	~FunctionBodyConsumer() {}

	void HandleTopLevelDecl(clang::Decl *D) {
		if (clang::FunctionDecl *FD = dyn_cast<clang::FunctionDecl>(D)) {
			if (clang::Stmt *S = FD->getBody()) {
				SF->VisitChildren(S);
			}
		}
	}

private:

	StmtFinder *SF;
};


Console::Console(bool debugMode) :
	_debugMode(debugMode),
	_prompt(">>> ")
{
	_options.C99 = true;
	// Declare exit() so users may call it without needing to #include <stdio.h>
	_lines.push_back(CodeLine("void exit(int status);", DeclLine));
}

Console::~Console()
{
	if (_linker)
		_linker->releaseModule();
}

const char * Console::prompt() const
{
	return _prompt.c_str();
}

const char * Console::input() const
{
	return _input.c_str();
}

string Console::genSource(string appendix)
{
	string src;
	for (unsigned i = 0; i < _lines.size(); ++i) {
		if (_lines[i].second == PrprLine) {
			src += _lines[i].first;
			src += "\n";
		} else if (_lines[i].second == DeclLine) {
			src += _lines[i].first;
			src += "\n";
		}
	}
	src += appendix;
	return src;
}

clang::Stmt * Console::lineToStmt(std::string line,
                                  clang::SourceManager *sm,
                                  std::string *src)
{
	*src += "void __ccons_temp() {\n";
	const unsigned pos = src->length();
	*src += line;
	*src += "\n}\n";

	clang::TextDiagnosticPrinter tdp(llvm::errs(), false, true, false);
	ProxyDiagnosticClient pdc(&tdp);
	clang::Diagnostic diag(&pdc);
	diag.setDiagnosticMapping(clang::diag::ext_implicit_function_decl,
	                          clang::diag::MAP_ERROR);
	diag.setSuppressSystemWarnings(true);

	StmtFinder finder(pos, *sm);
	FunctionBodyConsumer consumer(&finder);
	_parser.reset(new Parser(_options));
	_parser->parse(*src, sm, &diag, &consumer);

	if (pdc.hadErrors()) {
		src->clear();
		return NULL;
	}

	return finder.getStmt();
}

void Console::printGV(const llvm::Function *F,
                      const llvm::GenericValue& GV,
                      const clang::QualType& QT)
{
	string type = QT.getAsString();
	const llvm::FunctionType *FTy = F->getFunctionType();
	const llvm::Type *RetTy = FTy->getReturnType();
	switch (RetTy->getTypeID()) {
		case llvm::Type::IntegerTyID:
			if (QT->isUnsignedIntegerType())
				printf(("=> (" + type + ") %lu\n").c_str(), GV.IntVal.getZExtValue());
			else
				printf(("=> (" + type + ") %ld\n").c_str(), GV.IntVal.getZExtValue());
			return;
		case llvm::Type::FloatTyID:
			printf(("=> (" + type + ") %f\n").c_str(), GV.FloatVal);
			return;
		case llvm::Type::DoubleTyID:
			printf(("=> (" + type + ") %lf\n").c_str(), GV.DoubleVal);
			return;
		case llvm::Type::PointerTyID: {
			void *p = GVTOP(GV);
			// FIXME: this is a hack
			if (p && !strncmp(type.c_str(), "char", 4))
				printf(("=> (" + type + ") \"%s\"\n").c_str(), p);
			else
				printf(("=> (" + type + ") %p\n").c_str(), p);
			return;
		}
		case llvm::Type::VoidTyID:
			return;
		default:
			break;
	}

	assert(0 && "Unknown return type!");
}

Console::SrcRange Console::getStmtRange(const clang::Stmt *S,
                                        const clang::SourceManager& sm)
{
	clang::SourceLocation SLoc = sm.getInstantiationLoc(S->getLocStart());
	clang::SourceLocation ELoc = sm.getInstantiationLoc(S->getLocEnd());
	unsigned start = sm.getFileOffset(SLoc);
	unsigned end   = sm.getFileOffset(ELoc);
	end += clang::Lexer::MeasureTokenLength(ELoc, sm);
	return SrcRange(start, end);
}

bool Console::handleDeclStmt(const clang::DeclStmt *DS,
                             const string& src,
                             string *appendix,
                             string *funcBody,
                             std::vector<CodeLine> *moreLines,
                             const clang::SourceManager& sm)
{
	bool initializers = false;
	for (clang::DeclStmt::const_decl_iterator D = DS->decl_begin(),
			 E = DS->decl_end(); D != E; ++D) {
		if (const clang::VarDecl *VD = dyn_cast<clang::VarDecl>(*D)) {
			if (VD->getInit()) {
				initializers = true;
			}
		}
	}
	if (initializers) {
		std::vector<string> decls;
		std::vector<string> stmts;
		for (clang::DeclStmt::const_decl_iterator D = DS->decl_begin(),
				 E = DS->decl_end(); D != E; ++D) {
			if (const clang::VarDecl *VD = dyn_cast<clang::VarDecl>(*D)) {
				string decl = genVarDecl(VD->getType(), VD->getNameAsCString());
				if (const clang::Expr *I = VD->getInit()) {
					SrcRange range = getStmtRange(I, sm);
					if (I->isConstantInitializer(*_parser->getContext())) {
						// Keep the whole thing in the global context.
						std::stringstream global;
						global << decl << " = ";
						global << src.substr(range.first, range.second - range.first);
						*appendix += global.str() + ";\n";
					} else {
						// TODO: if it's an InitListExpr like {'a','b','c'}, then it's not
						//       allowed to exist in a normal initializer... (and we can't
						//       just place it in the global context since the params may
						//       be function calls or other non-constants). Thus it has to
						//       be split into array[0] = 'a'; array[1] = 'b'; .. etc. :(
						std::stringstream stmt;
						stmt << VD->getNameAsCString() << " = "
						     << src.substr(range.first, range.second - range.first) << ";";
						stmts.push_back(stmt.str());
						*appendix += decl + ";\n";
					}
				}
				decls.push_back(decl + ";");
			}
		}
		for (unsigned i = 0; i < decls.size(); ++i)
			moreLines->push_back(CodeLine("extern " + decls[i], DeclLine));
		for (unsigned i = 0; i < stmts.size(); ++i) {
			moreLines->push_back(CodeLine(stmts[i], StmtLine));
			*funcBody += stmts[i] + "\n";
		}
		return true;
	}
	return false;
}

string Console::genAppendix(const char *line,
                            string *fName,
                            clang::QualType& QT,
                            std::vector<CodeLine> *moreLines,
                            bool *hadErrors)
{
	bool wasExpr = false;
	string appendix;
	string funcBody;
	string src = genSource("");
	clang::SourceManager sm;

	while (isspace(*line)) line++;

	*hadErrors = false;
	if (*line == '#') {
		moreLines->push_back(CodeLine(line, PrprLine));
	} else if (const clang::Stmt *S = lineToStmt(line, &sm, &src)) {
		if (const clang::Expr *E = dyn_cast<clang::Expr>(S)) {
			QT = E->getType();
			funcBody = line;
			moreLines->push_back(CodeLine(line, StmtLine));
			wasExpr = true;
		} else if (const clang::DeclStmt *DS = dyn_cast<clang::DeclStmt>(S)) {
			if (!handleDeclStmt(DS, src, &appendix, &funcBody, moreLines, sm)) {
				moreLines->push_back(CodeLine(line, DeclLine));
				appendix += line;
				appendix += "\n";
			}
		} else {
			funcBody = line; // ex: if statement
			moreLines->push_back(CodeLine(line, StmtLine));
		}
	} else if (src.empty()) {
		std::cerr << "\nNote: Last line ignored due to errors.\n";
		*hadErrors = true;
	}

	if (!funcBody.empty()) {
		int funcNo = 0;
		for (unsigned i = 0; i < _lines.size(); ++i)
			funcNo += (_lines[i].second == StmtLine);
		*fName = "__ccons_anon" + to_string(funcNo);
		appendix += genFunc(wasExpr ? &QT : NULL, _parser->getContext(), *fName, funcBody);
		if (_debugMode)
			fprintf(stderr, "Generating function %s()...\n", fName->c_str());
	}

	return appendix;
}

void Console::process(const char *line)
{
	string fName;
	clang::QualType retType(0, 0);
	std::vector<CodeLine> linesToAppend;
	bool hadErrors;
	string appendix;
	string src;

	_buffer += line;
	Parser p(_options);
	int indentLevel;
	if (!p.analyzeInput(_buffer, indentLevel)) {
		// TODO: handle parse error!
		_input = string(indentLevel * 2, ' ');
		_prompt = "... ";
		return;
	}
	_prompt = ">>> ";
	_input = "";

	// process the input
	// TODO: figure out if input is a function, or a struct declaration, or
	//       something else that must exist in a global scope and act accordingly
	appendix = genAppendix(_buffer.c_str(), &fName, retType, &linesToAppend, &hadErrors);
	_buffer.clear();

	if (hadErrors)
		return;

	src = genSource(appendix);

	for (unsigned i = 0; i < linesToAppend.size(); ++i)
		_lines.push_back(linesToAppend[i]);

	clang::TextDiagnosticPrinter tdp(llvm::errs(), false, true, false);
	ProxyDiagnosticClient pdc(&tdp);
	clang::Diagnostic diag(&pdc);
	diag.setDiagnosticMapping(clang::diag::ext_implicit_function_decl,
	                          clang::diag::MAP_ERROR);
	diag.setSuppressSystemWarnings(true);

	llvm::OwningPtr<clang::CodeGenerator> codegen;
	codegen.reset(CreateLLVMCodeGen(diag, _options, "-", false));
	clang::SourceManager sm;
	Parser p2(_options); // we keep the other parser around because of QT...
	p2.parse(src, &sm, &diag, codegen.get());
	llvm::Module *module = codegen->ReleaseModule();
	if (module) {
		if (!_linker)
			_linker.reset(new llvm::Linker("ccons", "ccons"));
		string err;
		_linker->LinkInModule(module, &err);
		std::cout << err;
		// link it with the existing ones
		if (!fName.empty()) {
			module = _linker->getModule();
			if (!_engine)
				_engine.reset(llvm::ExecutionEngine::create(module));
			llvm::Function *F = module->getFunction(fName.c_str());
			assert(F && "Function was not found!");
			std::vector<llvm::GenericValue> params;
			if (_debugMode)
				fprintf(stderr, "Calling function %s()...\n", fName.c_str());
			llvm::GenericValue result = _engine->runFunction(F, params);
			if (retType.getTypePtr())
				printGV(F, result, retType);
		}
	}

	_parser.reset();
}

} // namespace ccons
