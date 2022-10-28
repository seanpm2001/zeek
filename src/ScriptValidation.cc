#include "zeek/ScriptValidation.h"

#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/Stmt.h"
#include "zeek/Traverse.h"

namespace zeek::detail
	{

// Validate context of break and next statement usage.
class BreakNextScriptValidation : public TraversalCallback
	{
public:
	TraversalCode PreStmt(const Stmt* stmt)
		{
		if ( ! StmtIsRelevant(stmt) )
			return TC_CONTINUE;

		stmt_depths[stmt->Tag()] += 1;

		if ( stmt->Tag() == STMT_BREAK && ! BreakStmtIsValid() )
			{
			zeek::reporter->PushLocation(stmt->GetLocationInfo());
			zeek::reporter->Error("break statement used outside of for, while or "
			                      "switch statement and not within a hook");
			zeek::reporter->PopLocation();
			}

		if ( stmt->Tag() == STMT_NEXT && ! NextStmtIsValid() )
			{
			zeek::reporter->PushLocation(stmt->GetLocationInfo());
			zeek::reporter->Error("next statement used outside of for or while statement");
			zeek::reporter->PopLocation();
			}

		return TC_CONTINUE;
		}

	TraversalCode PostStmt(const Stmt* stmt)
		{
		if ( ! StmtIsRelevant(stmt) )
			return TC_CONTINUE;

		--stmt_depths[stmt->Tag()];

		assert(stmt_depths[stmt->Tag()] >= 0);

		return TC_CONTINUE;
		}

	TraversalCode PreFunction(const zeek::Func* func)
		{
		if ( func->Flavor() == zeek::FUNC_FLAVOR_HOOK )
			++hook_depth;

		assert(hook_depth <= 1);

		return TC_CONTINUE;
		}

	TraversalCode PostFunction(const zeek::Func* func)
		{
		if ( func->Flavor() == zeek::FUNC_FLAVOR_HOOK )
			--hook_depth;

		assert(hook_depth >= 0);

		return TC_CONTINUE;
		}

private:
	bool StmtIsRelevant(const Stmt* stmt)
		{
		StmtTag tag = stmt->Tag();
		return tag == STMT_FOR || tag == STMT_WHILE || tag == STMT_SWITCH || tag == STMT_BREAK ||
		       tag == STMT_NEXT;
		}

	bool BreakStmtIsValid()
		{
		return hook_depth > 0 || stmt_depths[STMT_FOR] > 0 || stmt_depths[STMT_WHILE] > 0 ||
		       stmt_depths[STMT_SWITCH] > 0;
		}

	bool NextStmtIsValid() { return stmt_depths[STMT_FOR] > 0 || stmt_depths[STMT_WHILE] > 0; }

	std::unordered_map<const StmtTag, int> stmt_depths;
	int hook_depth = 0;
	};

// Validate CallExpr for non-builtin functions with a single parameter of type
// any. These are treated as potential untyped vararg functions during parsing
// when may not yet know if a function is a BIF or a script func.
class CallExprScriptValidation : public TraversalCallback
	{
public:
	TraversalCode PreExpr(const Expr* expr)
		{
		if ( expr->Tag() != EXPR_CALL )
			return TC_CONTINUE;

		const Expr* func_expr = expr->AsCallExpr()->Func();
		if ( func_expr->Tag() != EXPR_NAME )
			return TC_CONTINUE;

		const FuncType* func_type = func_expr->GetType()->AsFuncType();
		if ( func_type->Flavor() != FUNC_FLAVOR_FUNCTION )
			return TC_CONTINUE;

		zeek::RecordTypePtr params = func_type->Params();

		// Is it variadic?
		if ( params->NumFields() != 1 || params->FieldDecl(0)->type->Tag() != TYPE_ANY )
			return TC_CONTINUE;

		// If there's no val for a given name expression yet, we can't do much
		// statically as we don't know whether it'll be assigned a bif or a
		// script func.

		// However, hunch is we can just disallow variadic function calls
		// through script land variables pointing at BIFs and hope no one
		// gets upset (or we could give them a free pass).
		const NameExpr* name_expr = func_expr->AsNameExpr();
		if ( name_expr->Id()->HasVal() )
			{
			const zeek::ValPtr func_val = name_expr->Eval(nullptr);
			zeek::Func* func = func_val->AsFunc();

			// If this isn't a script function, give it a pass.
			if ( func->GetKind() != Func::SCRIPT_FUNC )
				return TC_CONTINUE;
			}

		// It's a script function (or script variable) with a single any
		// parameter. Ensure we only pass it a single argument, too.
		if ( expr->AsCallExpr()->Args()->Exprs().size() != 1 )
			{
			zeek::reporter->PushLocation(expr->GetLocationInfo());
			zeek::reporter->Error("argument type mismatch in function call");
			zeek::reporter->PopLocation();
			}

		return TC_CONTINUE;
		}
	};

void script_validation()
	{
	zeek::detail::BreakNextScriptValidation bn_cb;
	zeek::detail::traverse_all(&bn_cb);

	zeek::detail::CallExprScriptValidation ce_cb;
	zeek::detail::traverse_all(&ce_cb);
	}
	}
