// See the file "COPYING" in the main distribution directory for copyright.

// Optimization-related methods for Stmt classes.

#include "zeek/Stmt.h"

#include "zeek/Desc.h"
#include "zeek/Expr.h"
#include "zeek/Frame.h"
#include "zeek/Reporter.h"
#include "zeek/Traverse.h"
#include "zeek/script_opt/IDOptInfo.h"
#include "zeek/script_opt/Reduce.h"

namespace zeek::detail
	{

bool Stmt::IsReduced(Reducer* c) const
	{
	return true;
	}

StmtPtr Stmt::Reduce(Reducer* c)
	{
	auto this_ptr = ThisPtr();

	auto repl = c->ReplacementStmt(this_ptr);
	if ( repl )
		return repl;

	if ( c->ShouldOmitStmt(this) )
		{
		auto null = make_intrusive<NullStmt>();
		null->SetOriginal(this_ptr);
		return null;
		}

	c->SetCurrStmt(this);

	return DoReduce(c);
	}

StmtPtr Stmt::TransformMe(StmtPtr new_me, Reducer* c)
	{
	ASSERT(new_me != this);

	// Set the original prior to reduction, to support "original chains"
	// to ultimately resolve back to the source statement.
	new_me->SetOriginal(ThisPtr());
	return new_me->Reduce(c);
	}

void ExprListStmt::Inline(Inliner* inl)
	{
	auto& e = l->Exprs();
	for ( auto i = 0; i < e.length(); ++i )
		e.replace(i, e[i]->Inline(inl).release());
	}

bool ExprListStmt::IsReduced(Reducer* c) const
	{
	const ExprPList& e = l->Exprs();
	for ( const auto& expr : e )
		if ( ! expr->IsSingleton(c) )
			return NonReduced(expr);

	return true;
	}

StmtPtr ExprListStmt::DoReduce(Reducer* c)
	{
	if ( ! c->Optimizing() && IsReduced(c) )
		return ThisPtr();

	auto new_l = make_intrusive<ListExpr>();
	auto s = make_intrusive<StmtList>();

	ExprPList& e = l->Exprs();
	for ( auto& expr : e )
		{
		if ( c->Optimizing() )
			new_l->Append(c->OptExpr(expr));

		else if ( expr->IsSingleton(c) )
			new_l->Append({NewRef{}, expr});

		else
			{
			StmtPtr red_e_stmt;
			auto red_e = expr->ReduceToSingleton(c, red_e_stmt);
			new_l->Append(red_e);

			if ( red_e_stmt )
				s->Stmts().push_back(red_e_stmt);
			}
		}

	if ( c->Optimizing() )
		{
		l = new_l;
		return ThisPtr();
		}

	else
		{
		s->Stmts().push_back(DoSubclassReduce(new_l, c));
		return s->Reduce(c);
		}
	}

StmtPtr PrintStmt::Duplicate()
	{
	return SetSucc(new PrintStmt(l->Duplicate()->AsListExprPtr()));
	}

StmtPtr PrintStmt::DoSubclassReduce(ListExprPtr singletons, Reducer* c)
	{
	auto new_me = make_intrusive<PrintStmt>(singletons);
	new_me->SetOriginal(ThisPtr());
	return new_me;
	}

StmtPtr ExprStmt::Duplicate()
	{
	return SetSucc(new ExprStmt(e ? e->Duplicate() : nullptr));
	}

void ExprStmt::Inline(Inliner* inl)
	{
	if ( e )
		e = e->Inline(inl);
	}

bool ExprStmt::IsReduced(Reducer* c) const
	{
	if ( ! e || e->IsReduced(c) )
		return true;

	return NonReduced(e.get());
	}

StmtPtr ExprStmt::DoReduce(Reducer* c)
	{
	if ( ! e )
		// e can be nil for our derived classes (like ReturnStmt).
		return TransformMe(make_intrusive<NullStmt>(), c);

	auto t = e->Tag();

	if ( t == EXPR_NOP )
		return TransformMe(make_intrusive<NullStmt>(), c);

	if ( c->Optimizing() )
		{
		e = c->OptExpr(e);
		return ThisPtr();
		}

	if ( e->IsSingleton(c) )
		// No point evaluating.
		return TransformMe(make_intrusive<NullStmt>(), c);

	if ( (t == EXPR_ASSIGN || t == EXPR_CALL || t == EXPR_INDEX_ASSIGN ||
	      t == EXPR_FIELD_LHS_ASSIGN || t == EXPR_APPEND_TO || t == EXPR_ADD_TO ||
	      t == EXPR_REMOVE_FROM) &&
	     e->IsReduced(c) )
		return ThisPtr();

	StmtPtr red_e_stmt;

	if ( t == EXPR_CALL )
		// A bare call.  If we reduce it regularly, if
		// it has a non-void type it'll generate an
		// assignment to a temporary.
		red_e_stmt = e->ReduceToSingletons(c);
	else
		e = e->Reduce(c, red_e_stmt);

	if ( red_e_stmt )
		{
		auto s = make_intrusive<StmtList>(red_e_stmt, ThisPtr());
		return TransformMe(s, c);
		}

	else
		return ThisPtr();
	}

StmtPtr IfStmt::Duplicate()
	{
	return SetSucc(new IfStmt(e->Duplicate(), s1->Duplicate(), s2->Duplicate()));
	}

void IfStmt::Inline(Inliner* inl)
	{
	ExprStmt::Inline(inl);

	if ( s1 )
		s1->Inline(inl);
	if ( s2 )
		s2->Inline(inl);
	}

bool IfStmt::IsReduced(Reducer* c) const
	{
	if ( ! e->IsReducedConditional(c) )
		return NonReduced(e.get());

	return s1->IsReduced(c) && s2->IsReduced(c);
	}

StmtPtr IfStmt::DoReduce(Reducer* c)
	{
	StmtPtr red_e_stmt;

	if ( e->WillTransformInConditional(c) )
		e = e->ReduceToConditional(c, red_e_stmt);

	// First, assess some fundamental transformations.
	if ( e->Tag() == EXPR_NOT )
		{ // Change "if ( ! x ) s1 else s2" to "if ( x ) s2 else s1".
		auto s1_orig = s1;
		s1 = s2;
		s2 = s1_orig;

		e = e->GetOp1();
		}

	if ( e->Tag() == EXPR_OR_OR && c->BifurcationOkay() )
		{
		c->PushBifurcation();

		// Expand "if ( a || b ) s1 else s2" to
		// "if ( a ) s1 else { if ( b ) s1 else s2 }"
		auto a = e->GetOp1();
		auto b = e->GetOp2();

		auto s1_dup = s1 ? s1->Duplicate() : nullptr;
		s2 = make_intrusive<IfStmt>(b, s1_dup, s2);
		e = a;

		auto res = DoReduce(c);
		c->PopBifurcation();
		return res;
		}

	if ( e->Tag() == EXPR_AND_AND && c->BifurcationOkay() )
		{
		c->PushBifurcation();

		// Expand "if ( a && b ) s1 else s2" to
		// "if ( a ) { if ( b ) s1 else s2 } else s2"
		auto a = e->GetOp1();
		auto b = e->GetOp2();

		auto s2_dup = s2 ? s2->Duplicate() : nullptr;
		s1 = make_intrusive<IfStmt>(b, s1, s2_dup);
		e = a;

		auto res = DoReduce(c);
		c->PopBifurcation();
		return res;
		}

	s1 = s1->Reduce(c);
	s2 = s2->Reduce(c);

	if ( s1->Tag() == STMT_NULL && s2->Tag() == STMT_NULL )
		return TransformMe(make_intrusive<NullStmt>(), c);

	if ( c->Optimizing() )
		e = c->OptExpr(e);
	else
		{
		StmtPtr cond_red_stmt;
		e = e->ReduceToConditional(c, cond_red_stmt);

		if ( red_e_stmt && cond_red_stmt )
			red_e_stmt = make_intrusive<StmtList>(red_e_stmt, cond_red_stmt);
		else if ( cond_red_stmt )
			red_e_stmt = cond_red_stmt;
		}

	if ( e->IsConst() )
		{
		auto c_e = e->AsConstExprPtr();
		auto t = c_e->Value()->AsBool();

		if ( c->Optimizing() )
			return t ? s1 : s2;

		if ( t )
			return TransformMe(make_intrusive<StmtList>(red_e_stmt, s1), c);
		else
			return TransformMe(make_intrusive<StmtList>(red_e_stmt, s2), c);
		}

	if ( red_e_stmt )
		return TransformMe(make_intrusive<StmtList>(red_e_stmt, ThisPtr()), c);

	return ThisPtr();
	}

bool IfStmt::NoFlowAfter(bool ignore_break) const
	{
	if ( s1 && s2 )
		return s1->NoFlowAfter(ignore_break) && s2->NoFlowAfter(ignore_break);

	// Assuming the test isn't constant, the nonexistent branch
	// could be picked, so flow definitely continues afterwards.
	// (Constant branches will be pruned during reduction.)
	return false;
	}

IntrusivePtr<Case> Case::Duplicate()
	{
	if ( expr_cases )
		{
		auto new_exprs = expr_cases->Duplicate()->AsListExprPtr();
		return make_intrusive<Case>(new_exprs, nullptr, s->Duplicate());
		}

	IDPList* new_type_cases = nullptr;

	if ( type_cases )
		{
		new_type_cases = new IDPList();

		for ( auto tc : *type_cases )
			{
			zeek::Ref(tc);
			new_type_cases->append(tc);
			}
		}

	return make_intrusive<Case>(nullptr, new_type_cases, s->Duplicate());
	}

StmtPtr SwitchStmt::Duplicate()
	{
	auto new_cases = new case_list;

	loop_over_list(*cases, i) new_cases->append((*cases)[i]->Duplicate().release());

	return SetSucc(new SwitchStmt(e->Duplicate(), new_cases));
	}

void SwitchStmt::Inline(Inliner* inl)
	{
	ExprStmt::Inline(inl);

	for ( auto c : *cases )
		// In principle this can do the operation multiple times
		// for a given body, but that's no big deal as repeated
		// calls won't do anything.
		c->Body()->Inline(inl);
	}

bool SwitchStmt::IsReduced(Reducer* r) const
	{
	if ( ! e->IsReduced(r) )
		return NonReduced(e.get());

	if ( cases->length() == 0 )
		return false;

	for ( const auto& c : *cases )
		{
		if ( c->ExprCases() && ! c->ExprCases()->IsReduced(r) )
			return false;

		if ( c->TypeCases() && ! r->IDsAreReduced(c->TypeCases()) )
			return false;

		if ( ! c->Body()->IsReduced(r) )
			return false;
		}

	return true;
	}

StmtPtr SwitchStmt::DoReduce(Reducer* rc)
	{
	if ( cases->length() == 0 )
		// Degenerate.
		return make_intrusive<NullStmt>();

	auto s = make_intrusive<StmtList>();
	StmtPtr red_e_stmt;

	if ( rc->Optimizing() )
		e = rc->OptExpr(e);
	else
		e = e->Reduce(rc, red_e_stmt);

	// Note, the compiler checks for constant switch expressions.

	if ( red_e_stmt )
		s->Stmts().push_back(red_e_stmt);

	// Update type cases.
	for ( auto& i : case_label_type_list )
		{
		IDPtr idp = {NewRef{}, i.first};
		if ( idp->Name() )
			i.first = rc->UpdateID(idp).release();
		}

	for ( const auto& c : *cases )
		{
		auto c_e = c->ExprCases();
		if ( c_e )
			{
			StmtPtr c_e_stmt;
			auto red_cases = c_e->Reduce(rc, c_e_stmt);

			if ( c_e_stmt )
				s->Stmts().push_back(c_e_stmt);
			}

		auto c_t = c->TypeCases();
		if ( c_t )
			{
			for ( auto& c_t_i : *c_t )
				if ( c_t_i->Name() )
					c_t_i = rc->UpdateID({NewRef{}, c_t_i}).release();
			}

		c->UpdateBody(c->Body()->Reduce(rc));
		}

	if ( ! s->Stmts().empty() )
		{
		StmtPtr me = ThisPtr();
		auto pre_and_me = make_intrusive<StmtList>(s, me);
		return TransformMe(pre_and_me, rc);
		}

	return ThisPtr();
	}

bool SwitchStmt::NoFlowAfter(bool ignore_break) const
	{
	bool control_reaches_end = false;
	bool default_seen_with_no_flow_after = false;

	for ( const auto& c : *Cases() )
		{
		if ( ! c->Body()->NoFlowAfter(true) )
			return false;

		if ( (! c->ExprCases() || c->ExprCases()->Exprs().length() == 0) &&
		     (! c->TypeCases() || c->TypeCases()->length() == 0) )
			// We saw the default, and the test before this
			// one established that it has no flow after it.
			default_seen_with_no_flow_after = true;
		}

	return default_seen_with_no_flow_after;
	}

bool AddDelStmt::IsReduced(Reducer* c) const
	{
	return e->HasReducedOps(c);
	}

StmtPtr AddDelStmt::DoReduce(Reducer* c)
	{
	if ( c->Optimizing() )
		{
		e = c->OptExpr(e);
		return ThisPtr();
		}

	if ( e->Tag() != EXPR_INDEX && e->Tag() != EXPR_FIELD )
		Internal("bad \"add\"/\"delete\"");

	auto red_e_stmt = e->ReduceToSingletons(c);

	if ( red_e_stmt )
		{
		auto s = make_intrusive<StmtList>(red_e_stmt, ThisPtr());
		return TransformMe(s, c);
		}

	else
		return ThisPtr();
	}

StmtPtr AddStmt::Duplicate()
	{
	return SetSucc(new AddStmt(e->Duplicate()));
	}

StmtPtr DelStmt::Duplicate()
	{
	return SetSucc(new DelStmt(e->Duplicate()));
	}

StmtPtr EventStmt::Duplicate()
	{
	return SetSucc(new EventStmt(e->Duplicate()->AsEventExprPtr()));
	}

StmtPtr EventStmt::DoReduce(Reducer* c)
	{
	if ( c->Optimizing() )
		{
		e = c->OptExpr(e);
		event_expr = e->AsEventExprPtr();
		}

	else if ( ! event_expr->IsSingleton(c) )
		{
		StmtPtr red_e_stmt;
		auto ee_red = event_expr->Reduce(c, red_e_stmt);

		event_expr = ee_red->AsEventExprPtr();
		e = event_expr;

		if ( red_e_stmt )
			{
			auto s = make_intrusive<StmtList>(red_e_stmt, ThisPtr());
			return TransformMe(s, c);
			}
		}

	return ThisPtr();
	}

StmtPtr WhileStmt::Duplicate()
	{
	return SetSucc(new WhileStmt(loop_condition->Duplicate(), body->Duplicate()));
	}

void WhileStmt::Inline(Inliner* inl)
	{
	loop_condition = loop_condition->Inline(inl);

	if ( loop_cond_pred_stmt )
		loop_cond_pred_stmt->Inline(inl);
	if ( body )
		body->Inline(inl);
	}

bool WhileStmt::IsReduced(Reducer* c) const
	{
	// No need to check loop_cond_pred_stmt, as we create it reduced.
	return loop_condition->IsReducedConditional(c) && body->IsReduced(c);
	}

StmtPtr WhileStmt::DoReduce(Reducer* c)
	{
	if ( c->Optimizing() )
		loop_condition = c->OptExpr(loop_condition);
	else
		{
		if ( IsReduced(c) )
			{
			if ( ! c->IsPruning() )
				{
				// See comment below for the particulars
				// of this constructor.
				stmt_loop_condition = make_intrusive<ExprStmt>(STMT_EXPR, loop_condition);
				return ThisPtr();
				}
			}
		else
			loop_condition = loop_condition->ReduceToConditional(c, loop_cond_pred_stmt);
		}

	body = body->Reduce(c);

	// We use the more involved ExprStmt constructor here to bypass
	// its check for whether the expression is being ignored, since
	// we're not actually creating an ExprStmt for execution.
	stmt_loop_condition = make_intrusive<ExprStmt>(STMT_EXPR, loop_condition);

	if ( loop_cond_pred_stmt )
		loop_cond_pred_stmt = loop_cond_pred_stmt->Reduce(c);

	return ThisPtr();
	}

StmtPtr ForStmt::Duplicate()
	{
	auto expr_copy = e->Duplicate();

	auto new_loop_vars = new zeek::IDPList;
	loop_over_list(*loop_vars, i)
		{
		auto id = (*loop_vars)[i];
		zeek::Ref(id);
		new_loop_vars->append(id);
		}

	ForStmt* f;
	if ( value_var )
		f = new ForStmt(new_loop_vars, expr_copy, value_var);
	else
		f = new ForStmt(new_loop_vars, expr_copy);

	f->AddBody(body->Duplicate());

	return SetSucc(f);
	}

void ForStmt::Inline(Inliner* inl)
	{
	ExprStmt::Inline(inl);
	body->Inline(inl);
	}

bool ForStmt::IsReduced(Reducer* c) const
	{
	if ( ! e->IsReduced(c) )
		return NonReduced(e.get());

	if ( ! c->IDsAreReduced(loop_vars) )
		return false;

	if ( value_var && (value_var->IsBlank() || ! c->ID_IsReduced(value_var)) )
		return false;

	return body->IsReduced(c);
	}

StmtPtr ForStmt::DoReduce(Reducer* c)
	{
	if ( value_var && value_var->IsBlank() )
		{
		auto no_vv = make_intrusive<ForStmt>(loop_vars, e);
		no_vv->AddBody(body);
		return TransformMe(no_vv, c);
		}

	StmtPtr red_e_stmt;

	if ( c->Optimizing() )
		e = c->OptExpr(e);
	else
		{
		e = e->Reduce(c, red_e_stmt);
		c->UpdateIDs(loop_vars);

		if ( value_var )
			value_var = c->UpdateID(value_var);
		}

	body = body->Reduce(c);

	if ( body->Tag() == STMT_NULL )
		Warn("empty \"for\" body leaves loop variables in indeterminate state");

	if ( red_e_stmt )
		return TransformMe(make_intrusive<StmtList>(red_e_stmt, ThisPtr()), c);

	return ThisPtr();
	}

StmtPtr ReturnStmt::Duplicate()
	{
	return SetSucc(new ReturnStmt(e ? e->Duplicate() : nullptr, true));
	}

ReturnStmt::ReturnStmt(ExprPtr arg_e, bool ignored) : ExprStmt(STMT_RETURN, std::move(arg_e)) { }

bool ReturnStmt::IsReduced(Reducer* c) const
	{
	if ( ! e || e->IsSingleton(c) )
		return true;

	return NonReduced(e.get());
	}

StmtPtr ReturnStmt::DoReduce(Reducer* c)
	{
	if ( ! e )
		return ThisPtr();

	if ( c->Optimizing() )
		e = c->OptExpr(e);

	else if ( ! e->IsSingleton(c) )
		{
		StmtPtr red_e_stmt;
		e = e->ReduceToSingleton(c, red_e_stmt);

		if ( red_e_stmt )
			{
			auto s = make_intrusive<StmtList>(red_e_stmt, ThisPtr());
			return TransformMe(s, c);
			}
		}

	return ThisPtr();
	}

StmtList::StmtList(StmtPtr s1, StmtPtr s2) : Stmt(STMT_LIST)
	{
	if ( s1 )
		stmts.push_back(std::move(s1));
	if ( s2 )
		stmts.push_back(std::move(s2));
	}

StmtList::StmtList(StmtPtr s1, StmtPtr s2, StmtPtr s3) : Stmt(STMT_LIST)
	{
	if ( s1 )
		stmts.push_back(std::move(s1));
	if ( s2 )
		stmts.push_back(std::move(s2));
	if ( s3 )
		stmts.push_back(std::move(s3));
	}

StmtPtr StmtList::Duplicate()
	{
	auto new_sl = new StmtList();

	for ( auto& stmt : stmts )
		new_sl->stmts.push_back(stmt->Duplicate());

	return SetSucc(new_sl);
	}

void StmtList::Inline(Inliner* inl)
	{
	for ( const auto& stmt : stmts )
		stmt->Inline(inl);
	}

bool StmtList::IsReduced(Reducer* c) const
	{
	auto n = stmts.size();

	for ( auto i = 0; i < n; ++i )
		{
		auto& s_i = stmts[i];
		if ( ! s_i->IsReduced(c) )
			return false;

		if ( s_i->NoFlowAfter(false) && i < n - 1 )
			return false;
		}

	return true;
	}

StmtPtr StmtList::DoReduce(Reducer* c)
	{
	std::vector<StmtPtr> f_stmts;
	bool did_change = false;

	auto n = stmts.size();

	for ( auto i = 0; i < n; ++i )
		{
		if ( ReduceStmt(i, f_stmts, c) )
			did_change = true;

		if ( i < n - 1 && stmts[i]->NoFlowAfter(false) )
			{
			did_change = true;
			break;
			}

		if ( reporter->Errors() > 0 )
			return ThisPtr();
		}

	if ( f_stmts.empty() )
		return TransformMe(make_intrusive<NullStmt>(), c);

	if ( f_stmts.size() == 1 )
		return f_stmts[0]->Reduce(c);

	if ( did_change )
		{
		ResetStmts(std::move(f_stmts));
		return Reduce(c);
		}

	return ThisPtr();
	}

bool StmtList::ReduceStmt(int& s_i, std::vector<StmtPtr>& f_stmts, Reducer* c)
	{
	bool did_change = false;
	auto stmt = stmts[s_i];
	auto old_stmt = stmt;

	stmt = stmt->Reduce(c);

	if ( stmt != old_stmt )
		did_change = true;

	if ( c->Optimizing() && stmt->Tag() == STMT_EXPR )
		{
		// There are two potential optimizations that affect
		// whether we keep assignment statements.  The first is
		// for potential assignment chains like
		//
		//	tmp1 = x;
		//	tmp2 = tmp1;
		//
		// where we can change this pair to simply "tmp2 = x", assuming
		// no later use of tmp1.
		//
		// In addition, if we have "tmp1 = e" and "e" is an expression
		// already computed into another temporary (say tmp0) that's
		// safely usable at this point, then we can elide the tmp1
		// assignment entirely.
		auto s_e = stmt->AsExprStmt();
		auto e = s_e->StmtExpr();

		if ( e->Tag() != EXPR_ASSIGN )
			{
			f_stmts.push_back(std::move(stmt));
			return false;
			}

		auto a = e->AsAssignExpr();
		auto lhs = a->Op1()->AsRefExprPtr()->Op();

		if ( lhs->Tag() != EXPR_NAME )
			{
			f_stmts.push_back(std::move(stmt));
			return false;
			}

		auto var = lhs->AsNameExpr();
		auto rhs = a->GetOp2();

		if ( s_i < stmts.size() - 1 )
			{
			// See if we can compress an assignment chain.
			auto& s_i_succ = stmts[s_i + 1];

			// Don't reduce s_i_succ.  If it's what we're
			// looking for, it's already reduced.  Plus
			// that's what Reducer::MergeStmts (not that
			// it really matters, per the comment there).
			auto merge = c->MergeStmts(var, rhs, s_i_succ);
			if ( merge )
				{
				f_stmts.push_back(std::move(merge));

				// Skip both this statement and the next,
				// now that we've substituted the merge.
				++s_i;
				return true;
				}
			}

		if ( c->IsCSE(a, var, rhs.get()) )
			{
			// printf("discarding %s as unnecessary\n", obj_desc(a));
			// Skip this now unnecessary statement.
			return true;
			}
		}

	if ( stmt->Tag() == STMT_LIST )
		{ // inline the list
		auto sl = stmt->AsStmtList();

		for ( auto& sub_stmt : sl->Stmts() )
			f_stmts.push_back(sub_stmt);

		did_change = true;
		}

	else if ( stmt->Tag() == STMT_NULL )
		// skip it
		did_change = true;

	else
		f_stmts.push_back(std::move(stmt));

	return did_change;
	}

bool StmtList::NoFlowAfter(bool ignore_break) const
	{
	for ( auto& s : stmts )
		{
		// For "break" statements, if ignore_break is set then
		// by construction flow *does* go to after this statement
		// list.  If we just used the second test below, then
		// while the "break" would indicate there's flow after it,
		// if there's dead code following that includes a "return",
		// this would in fact be incorrect.
		if ( ignore_break && s->Tag() == STMT_BREAK )
			return false;

		if ( s->NoFlowAfter(ignore_break) )
			return true;
		}

	return false;
	}

StmtPtr InitStmt::Duplicate()
	{
	// Need to duplicate the initializer list since later reductions
	// can modify it in place.
	std::vector<IDPtr> new_inits;
	for ( const auto& id : inits )
		new_inits.push_back(id);

	return SetSucc(new InitStmt(new_inits));
	}

bool InitStmt::IsReduced(Reducer* c) const
	{
	return c->IDsAreReduced(inits);
	}

StmtPtr InitStmt::DoReduce(Reducer* c)
	{
	c->UpdateIDs(inits);
	return ThisPtr();
	}

StmtPtr AssertStmt::Duplicate()
	{
	return SetSucc(new AssertStmt(cond->Duplicate(), msg ? msg->Duplicate() : nullptr));
	}

bool AssertStmt::IsReduced(Reducer* c) const
	{
	return false;
	}

StmtPtr AssertStmt::DoReduce(Reducer* c)
	{
	return make_intrusive<NullStmt>();
	}

bool WhenInfo::HasUnreducedIDs(Reducer* c) const
	{
	for ( auto& cp : *cl )
		{
		auto cid = cp.Id();

		if ( when_new_locals.count(cid.get()) == 0 && ! c->ID_IsReduced(cp.Id()) )
			return true;
		}

	for ( auto& l : when_expr_locals )
		if ( ! c->ID_IsReduced(l) )
			return true;

	return false;
	}

void WhenInfo::UpdateIDs(Reducer* c)
	{
	for ( auto& cp : *cl )
		{
		auto& cid = cp.Id();
		if ( when_new_locals.count(cid.get()) == 0 )
			cp.SetID(c->UpdateID(cid));
		}

	for ( auto& l : when_expr_locals )
		l = c->UpdateID(l);
	}

StmtPtr WhenStmt::Duplicate()
	{
	return SetSucc(new WhenStmt(std::make_shared<WhenInfo>(wi.get())));
	}

bool WhenStmt::IsReduced(Reducer* c) const
	{
	if ( wi->HasUnreducedIDs(c) )
		return false;

	if ( ! wi->Lambda()->IsReduced(c) )
		return false;

	if ( ! wi->TimeoutExpr() )
		return true;

	return wi->TimeoutExpr()->IsReduced(c);
	}

StmtPtr WhenStmt::DoReduce(Reducer* c)
	{
	if ( ! c->Optimizing() )
		{
		wi->UpdateIDs(c);
		(void)wi->Lambda()->ReduceToSingletons(c);
		}

	auto e = wi->TimeoutExpr();

	if ( ! e )
		return ThisPtr();

	if ( c->Optimizing() )
		wi->SetTimeoutExpr(c->OptExpr(e));

	else if ( ! e->IsSingleton(c) )
		{
		StmtPtr red_e_stmt;
		auto new_e = e->ReduceToSingleton(c, red_e_stmt);
		wi->SetTimeoutExpr(new_e);

		if ( red_e_stmt )
			{
			auto s = make_intrusive<StmtList>(red_e_stmt, ThisPtr());
			return TransformMe(s, c);
			}
		}

	return ThisPtr();
	}

CatchReturnStmt::CatchReturnStmt(StmtPtr _block, NameExprPtr _ret_var) : Stmt(STMT_CATCH_RETURN)
	{
	block = _block;
	ret_var = _ret_var;
	}

ValPtr CatchReturnStmt::Exec(Frame* f, StmtFlowType& flow)
	{
	RegisterAccess();

	auto val = block->Exec(f, flow);

	if ( flow == FLOW_RETURN )
		flow = FLOW_NEXT;

	if ( ret_var )
		f->SetElement(ret_var->Id()->Offset(), val);

	// Note, do *not* return the value!  That's taken as a signal
	// that a full return executed.
	return nullptr;
	}

bool CatchReturnStmt::IsPure() const
	{
	// The ret_var is pure by construction.
	return block->IsPure();
	}

StmtPtr CatchReturnStmt::Duplicate()
	{
	auto rv_dup = ret_var->Duplicate();
	auto rv_dup_ptr = rv_dup->AsNameExprPtr();
	return SetSucc(new CatchReturnStmt(block->Duplicate(), rv_dup_ptr));
	}

StmtPtr CatchReturnStmt::DoReduce(Reducer* c)
	{
	block = block->Reduce(c);

	if ( block->Tag() == STMT_RETURN )
		{
		// The whole thing reduced to a bare return.  This can
		// happen due to constant propagation.
		auto ret = block->AsReturnStmt();
		auto ret_e = ret->StmtExprPtr();

		if ( ! ret_e )
			{
			if ( ret_var )
				reporter->InternalError("inlining inconsistency: no return value");

			return make_intrusive<NullStmt>();
			}

		auto rv_dup = ret_var->Duplicate();
		auto ret_e_dup = ret_e->Duplicate();

		auto assign = make_intrusive<AssignExpr>(rv_dup, ret_e_dup, false);
		assign_stmt = make_intrusive<ExprStmt>(assign);

		if ( ret_e_dup->Tag() == EXPR_CONST )
			{
			auto ce = ret_e_dup->AsConstExpr();
			rv_dup->AsNameExpr()->Id()->GetOptInfo()->SetConst(ce);
			}

		return assign_stmt;
		}

	return ThisPtr();
	}

void CatchReturnStmt::StmtDescribe(ODesc* d) const
	{
	Stmt::StmtDescribe(d);
	block->Describe(d);
	DescribeDone(d);
	}

TraversalCode CatchReturnStmt::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	block->Traverse(cb);

	if ( ret_var )
		ret_var->Traverse(cb);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}

CheckAnyLenStmt::CheckAnyLenStmt(ExprPtr arg_e, int _expected_len)
	: ExprStmt(STMT_CHECK_ANY_LEN, std::move(arg_e))
	{
	expected_len = _expected_len;
	}

ValPtr CheckAnyLenStmt::Exec(Frame* f, StmtFlowType& flow)
	{
	RegisterAccess();
	flow = FLOW_NEXT;

	auto& v = e->Eval(f)->AsListVal()->Vals();

	if ( v.size() != static_cast<size_t>(expected_len) )
		reporter->ExprRuntimeError(e.get(), "mismatch in list lengths");

	return nullptr;
	}

StmtPtr CheckAnyLenStmt::Duplicate()
	{
	return SetSucc(new CheckAnyLenStmt(e->Duplicate(), expected_len));
	}

bool CheckAnyLenStmt::IsReduced(Reducer* c) const
	{
	return true;
	}

StmtPtr CheckAnyLenStmt::DoReduce(Reducer* c)
	{
	// These are created in reduced form.
	return ThisPtr();
	}

void CheckAnyLenStmt::StmtDescribe(ODesc* d) const
	{
	Stmt::StmtDescribe(d);

	e->Describe(d);
	if ( ! d->IsBinary() )
		d->Add(".length == ");

	d->Add(expected_len);

	DescribeDone(d);
	}

	} // namespace zeek::detail
