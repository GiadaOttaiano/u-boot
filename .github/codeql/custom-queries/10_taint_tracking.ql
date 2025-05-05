/**
 * @kind path-problem
*/

import cpp
import semmle.code.cpp.dataflow.TaintTracking

class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation m |
      m.getMacro().getName().regexpMatch("^ntoh(?:s|l|ll)$") and
      this = m.getExpr()
    )
  }
}

module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Expr e |
      e instanceof NetworkByteSwap and
      source.asExpr() = e
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fc |
      fc.getTarget().hasName("memcpy") and
      sink.asExpr() = fc.getArgument(2) // il terzo argomento è la "length"
    )
  }
}

module MyTaint = TaintTracking::Global<MyConfig>;
import MyTaint::PathGraph

from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"