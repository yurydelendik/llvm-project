//===-- DWARFEvaluator.h ----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_EXPRESSION_DWARFEVALUATOR_H
#define LLDB_EXPRESSION_DWARFEVALUATOR_H

#include "lldb/lldb-private.h"
#include <vector>

namespace lldb_private {

class DWARFExpression;

/// \class DWARFEvaluator DWARFEvaluator.h
/// "lldb/Expression/DWARFEvaluator.h" Evaluates DWARF opcodes.
///
class DWARFEvaluator {
public:
  /// Crates a DWARF location expression evaluator
  ///
  /// \param[in] dwarf_expression
  ///     The DWARF expression to evaluate.
  ///
  /// \param[in] exe_ctx
  ///     The execution context in which to evaluate the location
  ///     expression.  The location expression may access the target's
  ///     memory, especially if it comes from the expression parser.
  ///
  ///  \param[in] reg_ctx
  ///     An optional parameter which provides a RegisterContext for use
  ///     when evaluating the expression (i.e. for fetching register values).
  ///     Normally this will come from the ExecutionContext's StackFrame but
  ///     in the case where an expression needs to be evaluated while building
  ///     the stack frame list, this short-cut is available.
  ///
  /// \param[in] initial_value_ptr
  ///     A value to put on top of the interpreter stack before evaluating
  ///     the expression, if the expression is parametrized.  Can be NULL.
  ///
  /// \param[in] object_address_ptr
  ///
  DWARFEvaluator(const DWARFExpression &dwarf_expression,
                 ExecutionContext *exe_ctx, RegisterContext *reg_ctx,
                 const Value *initial_value_ptr,
                 const Value *object_address_ptr);

  /// DWARFEvaluator protocol.
  /// \{

  /// Evaluate the DWARF location expression
  ///
  /// \param[in] result
  ///     A value into which the result of evaluating the expression is
  ///     to be placed.
  ///
  /// \param[in] error_ptr
  ///     If non-NULL, used to report errors in expression evaluation.
  ///
  /// \return
  ///     True on success; false otherwise.  If error_ptr is non-NULL,
  ///     details of the failure are provided through it.
  virtual bool Evaluate(Value &result, Status *error_ptr);

  /// Evaluate the DWARF location expression with the opcodes specified.
  ///
  /// \param[in] opcodes
  ///     The DWARF opcodes to evaluate.
  ///
  /// \param[in] result
  ///     A value into which the result of evaluating the expression is
  ///     to be placed.
  ///
  /// \param[in] error_ptr
  ///     If non-NULL, used to report errors in expression evaluation.
  ///
  /// \return
  ///     True on success; false otherwise.  If error_ptr is non-NULL,
  ///     details of the failure are provided through it.
  virtual bool Evaluate(const DataExtractor &opcodes, Value &result,
                        Status *error_ptr);

  /// Evaluates a specific DWARF opcode in the context of a DWARF expression
  virtual bool Evaluate(const uint8_t op, Process *process, StackFrame *frame,
                        std::vector<Value> &stack, const DataExtractor &opcodes,
                        lldb::offset_t &offset, Value &pieces,
                        uint64_t &op_piece_offset, Log *log, Status *error_ptr);

  /// \}

protected:
  const DWARFExpression &m_dwarf_expression;
  ExecutionContext *m_exe_ctx;
  RegisterContext *m_reg_ctx;
  const Value *m_initial_value_ptr;
  const Value *m_object_address_ptr;

private:
  DWARFEvaluator(const DWARFEvaluator &) = delete;
  const DWARFEvaluator &operator=(const DWARFEvaluator &) = delete;
};

} // namespace lldb_private

#endif // LLDB_EXPRESSION_DWARFEVALUATOR_H
