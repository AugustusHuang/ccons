#ifndef CCONS_CONSOLE_H
#define CCONS_CONSOLE_H

//
// Defines the IConsole interface used by ccons.cpp to process user input,
// as well as the concrete Console class, implementing said interface and
// providing C input processing using the clang and llvm libraries.
//
// Part of ccons, the interactive console for the C programming language.
//
// Copyright (c) 2009 Alexei Svitkine. This file is distributed under the
// terms of MIT Open Source License. See file LICENSE for details.
//

#include <stdio.h>

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

// #include <llvm/ADT/OwningPtr.h>
// OwningPtr<T> replaced by std::unique_ptr<T>.
// --- Augustus Huang, June 30 2015

#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/raw_os_ostream.h>

#include <clang/Basic/LangOptions.h>
#include <clang/Basic/TargetOptions.h>

namespace llvm {
	struct GenericValue;
	class ExecutionEngine;
	class Function;
	class Linker;
	class Module;
} // namespace llvm

namespace clang {
	class DeclStmt;
	class Expr;
	class Preprocessor;
	class QualType;
	class SourceManager;
	class Stmt;
	class VarDecl;
} // namespace clang

namespace ccons {

class Parser;
class DiagnosticsProvider;
class MacroDetector;

//
// IConsole interface
//

class IConsole {

public:

	virtual ~IConsole() {}

	// Returns the prompt that should be presented to the user.
	virtual const char *prompt() const = 0;

	// Returns the initial input string that should be prepended.
	virtual const char *input() const = 0;

	// Process the specified line of user input.
	virtual void process(const char *line) = 0;

};

//
// Console implementation
//

class Console : public IConsole {

public:

	Console(bool _debugMode,
	        std::ostream& out = std::cout,
	        std::ostream& err = std::cerr);
	virtual ~Console();

	const char *prompt() const;
	const char *input() const;
	void process(const char *line);

private:

	enum LineType {
		StmtLine,
		DeclLine,
		PrprLine,
	};

	typedef std::pair<std::string, LineType> CodeLine;

	void reportInputError();

	bool shouldPrintCString(const char *p);
	void printGV(const llvm::Function *F,
	             const llvm::GenericValue& GV,
	             const clang::QualType& QT);
	void processVarDecl(const std::string& src,
	                    const clang::VarDecl *VD,
	                    std::vector<std::string> *decls,
	                    std::vector<std::string> *stmts,
	                    std::string *appendix);
	bool handleDeclStmt(const clang::DeclStmt *DS,
	                    const std::string& src,
	                    std::string *appendix,
	                    std::string *funcBody,
	                    std::vector<CodeLine> *moreLines);
	std::string genAppendix(const char *source,
	                        const char *line,
	                        std::string *fName,
	                        clang::QualType& QT,
	                        std::vector<CodeLine> *moreLines,
	                        bool *hadErrors);
	std::string genSource(const std::string& appendix) const;
	int splitInput(const std::string& source,
	               const std::string& input,
	               std::vector<std::string> *statements);
	clang::Stmt *locateStmt(const std::string& line,
	                        std::string *src);

	bool compileLinkAndRun(const std::string& src,
                           const std::string& fName,
                           const clang::QualType& retType);

	bool _debugMode;
	std::ostream& _out;
	std::ostream& _err;
	mutable llvm::raw_os_ostream _raw_err;
	clang::LangOptions _options;
	clang::TargetOptions _targetOptions;
	std::unique_ptr<Parser> _parser;
	llvm::LLVMContext _context;
	std::unique_ptr<llvm::Module> _linkerModule;
	std::unique_ptr<llvm::Linker> _linker;
	std::unique_ptr<llvm::ExecutionEngine> _engine;
	std::unique_ptr<DiagnosticsProvider> _dp;
	MacroDetector *_macros;
	std::vector<std::string> _prevMacros;
	std::vector<CodeLine> _lines;
	std::string _buffer;
	std::string _prompt;
	std::string _input;
	unsigned _funcNo;
	FILE *_tempFile;

};

// Some MCJIT helper directly ported from example/Kaleidoscope.
class MCJITObjectCache : public ObjectCache {
public:
	MCJITObjectCache() {
		// Set IR cache directory
		sys::fs::current_path(CacheDir);
		sys::path::append(CacheDir, "toy_object_cache");
	}

	virtual ~MCJITObjectCache() {}

	virtual void notifyObjectCompiled(const Module *M, const MemoryBuffer *Obj)
	{
		// Get the ModuleID

		const std::string ModuleID = M->getModuleIdentifier();

		// If we've flagged this as an IR file, cache it
		if (0 == ModuleID.compare(0, 3, "IR:")) {
			std::string IRFileName = ModuleID.substr(3);
			SmallString<128>IRCacheFile = CacheDir;
			sys::path::append(IRCacheFile, IRFileName);
			if (!sys::fs::exists(CacheDir.str()) && sys::fs::create_directory(CacheDir.str())) {
				fprintf(stderr, "Unable to create cache directory\n");
				return;
			}
			std::string ErrStr;
			raw_fd_ostream IRObjectFile(IRCacheFile.c_str(),
					ErrStr, raw_fd_ostream::F_Binary);
			IRObjectFile << Obj->getBuffer();
		}
	}

	// MCJIT will call this function before compiling any module
	// MCJIT takes ownership of both the MemoryBuffer object and the memory
	// to which it refers.
	virtual MemoryBuffer* getObject(const Module* M) {
		// Get the ModuleID
		const std::string ModuleID = M->getModuleIdentifier();

		// If we've flagged this as an IR file, cache it
		if (0 == ModuleID.compare(0, 3, "IR:")) {
			std::string IRFileName = ModuleID.substr(3);
			SmallString<128> IRCacheFile = CacheDir;
			sys::path::append(IRCacheFile, IRFileName);
			if (!sys::fs::exists(IRCacheFile.str())) {
				// This file isn't in our cache
				return NULL;
			}
			std::unique_ptr<MemoryBuffer> IRObjectBuffer;
			MemoryBuffer::getFile(IRCacheFile.c_str(), IRObjectBuffer, -1, false);
			// MCJIT will want to write into this buffer, and we don't want that
			// because the file has probably just been mmapped.  Instead we mak
			// a copy.  The filed-based buffer will be released when it goes
			// out of scope.
			return MemoryBuffer::getMemBufferCopy(IRObjectBuffer->getBuffer());
		}

		return NULL;
	}

private:
  SmallString<128> CacheDir;
};

class BaseHelper
{
public:
	BaseHelper() {}
	virtual ~BaseHelper() {}

	virtual llvm::Function *getFunction(const std::string FnName) = 0;
	virtual llvm::Module *getModuleForNewFunction() = 0;
	virtual void *getPointerToFunction(llvm::Function *F) = 0;
	virtual void *getPointerToNamedFunction(const std::string& Name) = 0;
	virtual void closeCurrentModule() = 0;
	virtual void runFPM(Function& F) = 0;
	virtual void dump() = 0;
};

class MCJITHelper : public BaseHelper
{
public:
	  MCJITHelper(LLVMContext& C) : Context(C), CurrentModule(NULL) {
    if (!InputIR.empty()) {
      Module *M = parseInputIR(InputIR, Context);
      Modules.push_back(M);
      if (!EnableLazyCompilation)
        compileModule(M);
    }
  }
  ~MCJITHelper();

  Function *getFunction(const std::string FnName);
  Module *getModuleForNewFunction();
  void *getPointerToFunction(Function* F);
  void *getPointerToNamedFunction(const std::string &Name);
  void closeCurrentModule();
  virtual void runFPM(Function &F) {} // Not needed, see compileModule
  void dump();

protected:
  ExecutionEngine *compileModule(Module *M);

private:
  typedef std::vector<Module*> ModuleVector;

  MCJITObjectCache OurObjectCache;

  LLVMContext  &Context;
  ModuleVector  Modules;

  std::map<Module *, ExecutionEngine *> EngineMap;

  Module       *CurrentModule;
};

class HelpingMemoryManager : public SectionMemoryManager
{
  HelpingMemoryManager(const HelpingMemoryManager&) LLVM_DELETED_FUNCTION;
  void operator=(const HelpingMemoryManager&) LLVM_DELETED_FUNCTION;

public:
  HelpingMemoryManager(MCJITHelper *Helper) : MasterHelper(Helper) {}
  virtual ~HelpingMemoryManager() {}

  /// This method returns the address of the specified function.
  /// Our implementation will attempt to find functions in other
  /// modules associated with the MCJITHelper to cross link functions
  /// from one generated module to another.
  ///
  /// If \p AbortOnFailure is false and no function with the given name is
  /// found, this function returns a null pointer. Otherwise, it prints a
  /// message to stderr and aborts.
  virtual void *getPointerToNamedFunction(const std::string &Name,
                                          bool AbortOnFailure = true);
private:
  MCJITHelper *MasterHelper;
};

void *HelpingMemoryManager::getPointerToNamedFunction(const std::string &Name,
                                        bool AbortOnFailure)
{
  // Try the standard symbol resolution first, but ask it not to abort.
  void *pfn = RTDyldMemoryManager::getPointerToNamedFunction(Name, false);
  if (pfn)
    return pfn;

  pfn = MasterHelper->getPointerToNamedFunction(Name);
  if (!pfn && AbortOnFailure)
    report_fatal_error("Program used external function '" + Name +
                        "' which could not be resolved!");
  return pfn;
}

MCJITHelper::~MCJITHelper()
{
  // Walk the vector of modules.
  ModuleVector::iterator it, end;
  for (it = Modules.begin(), end = Modules.end();
       it != end; ++it) {
    // See if we have an execution engine for this module.
    std::map<Module*, ExecutionEngine*>::iterator mapIt = EngineMap.find(*it);
    // If we have an EE, the EE owns the module so just delete the EE.
    if (mapIt != EngineMap.end()) {
      delete mapIt->second;
    } else {
      // Otherwise, we still own the module.  Delete it now.
      delete *it;
    }
  }
}

Function *MCJITHelper::getFunction(const std::string FnName) {
  ModuleVector::iterator begin = Modules.begin();
  ModuleVector::iterator end = Modules.end();
  ModuleVector::iterator it;
  for (it = begin; it != end; ++it) {
    Function *F = (*it)->getFunction(FnName);
    if (F) {
      if (*it == CurrentModule)
          return F;

      assert(CurrentModule != NULL);

      // This function is in a module that has already been JITed.
      // We just need a prototype for external linkage.
      Function *PF = CurrentModule->getFunction(FnName);
      if (PF && !PF->empty()) {
        ErrorF("redefinition of function across modules");
        return 0;
      }

      // If we don't have a prototype yet, create one.
      if (!PF)
        PF = Function::Create(F->getFunctionType(),
                                      Function::ExternalLinkage,
                                      FnName,
                                      CurrentModule);
      return PF;
    }
  }
  return NULL;
}

Module *MCJITHelper::getModuleForNewFunction() {
  // If we have a Module that hasn't been JITed, use that.
  if (CurrentModule)
    return CurrentModule;

  // Otherwise create a new Module.
  std::string ModName = GenerateUniqueName("mcjit_module_");
  Module *M = new Module(ModName, Context);
  Modules.push_back(M);
  CurrentModule = M;

  return M;
}

ExecutionEngine *MCJITHelper::compileModule(Module *M) {
  assert(EngineMap.find(M) == EngineMap.end());

  if (M == CurrentModule)
    closeCurrentModule();

  std::string ErrStr;
  ExecutionEngine *EE = EngineBuilder(M)
                            .setErrorStr(&ErrStr)
                            .setMCJITMemoryManager(new HelpingMemoryManager(this))
                            .create();
  if (!EE) {
    fprintf(stderr, "Could not create ExecutionEngine: %s\n", ErrStr.c_str());
    exit(1);
  }

  if (UseObjectCache)
    EE->setObjectCache(&OurObjectCache);
  // Get the ModuleID so we can identify IR input files
  const std::string ModuleID = M->getModuleIdentifier();

  // If we've flagged this as an IR file, it doesn't need function passes run.
  if (0 != ModuleID.compare(0, 3, "IR:")) {
    FunctionPassManager *FPM = 0;

    // Create a FPM for this module
    FPM = new FunctionPassManager(M);

    // Set up the optimizer pipeline.  Start with registering info about how the
    // target lays out data structures.
    FPM->add(new DataLayout(*EE->getDataLayout()));
    // Provide basic AliasAnalysis support for GVN.
    FPM->add(createBasicAliasAnalysisPass());
    // Promote allocas to registers.
    FPM->add(createPromoteMemoryToRegisterPass());
    // Do simple "peephole" optimizations and bit-twiddling optzns.
    FPM->add(createInstructionCombiningPass());
    // Reassociate expressions.
    FPM->add(createReassociatePass());
    // Eliminate Common SubExpressions.
    FPM->add(createGVNPass());
    // Simplify the control flow graph (deleting unreachable blocks, etc).
    FPM->add(createCFGSimplificationPass());

    FPM->doInitialization();

    // For each function in the module
    Module::iterator it;
    Module::iterator end = M->end();
    for (it = M->begin(); it != end; ++it) {
      // Run the FPM on this function
      FPM->run(*it);
    }

    delete FPM;
  }

  EE->finalizeObject();

  // Store this engine
  EngineMap[M] = EE;

  return EE;
}

void *MCJITHelper::getPointerToFunction(Function* F) {
  // Look for this function in an existing module
  ModuleVector::iterator begin = Modules.begin();
  ModuleVector::iterator end = Modules.end();
  ModuleVector::iterator it;
  std::string FnName = F->getName();
  for (it = begin; it != end; ++it) {
    Function *MF = (*it)->getFunction(FnName);
    if (MF == F) {
      std::map<Module*, ExecutionEngine*>::iterator eeIt = EngineMap.find(*it);
      if (eeIt != EngineMap.end()) {
        void *P = eeIt->second->getPointerToFunction(F);
        if (P)
          return P;
      } else {
        ExecutionEngine *EE = compileModule(*it);
        void *P = EE->getPointerToFunction(F);
        if (P)
          return P;
      }
    }
  }
  return NULL;
}

void MCJITHelper::closeCurrentModule() {
    // If we have an open module (and we should), pack it up
  if (CurrentModule) {
    CurrentModule = NULL;
  }
}

void *MCJITHelper::getPointerToNamedFunction(const std::string &Name)
{
  // Look for the functions in our modules, compiling only as necessary
  ModuleVector::iterator begin = Modules.begin();
  ModuleVector::iterator end = Modules.end();
  ModuleVector::iterator it;
  for (it = begin; it != end; ++it) {
    Function *F = (*it)->getFunction(Name);
    if (F && !F->empty()) {
      std::map<Module*, ExecutionEngine*>::iterator eeIt = EngineMap.find(*it);
      if (eeIt != EngineMap.end()) {
        void *P = eeIt->second->getPointerToFunction(F);
        if (P)
          return P;
      } else {
        ExecutionEngine *EE = compileModule(*it);
        void *P = EE->getPointerToFunction(F);
        if (P)
          return P;
      }
    }
  }
  return NULL;
}

void MCJITHelper::dump()
{
  ModuleVector::iterator begin = Modules.begin();
  ModuleVector::iterator end = Modules.end();
  ModuleVector::iterator it;
  for (it = begin; it != end; ++it)
    (*it)->dump();
}

} // namespace ccons

#endif // CCONS_CONSOLE_H
