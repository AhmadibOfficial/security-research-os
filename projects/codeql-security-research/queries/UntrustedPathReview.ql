/**
 * @name Untrusted Python file path candidate for manual review
 * @description Identify paths influenced by untrusted input reaching filesystem operations.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id ahmadib/untrusted-python-file-path
 * @tags security
 *       external/cwe/cwe-022
 */
import python
import semmle.python.security.dataflow.PathInjectionQuery
import PathInjectionFlow::PathGraph

from PathInjectionFlow::PathNode source, PathInjectionFlow::PathNode sink
where PathInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential untrusted file path from a $@ requires authorization and impact review.",
  source.getNode(), "user-controlled source"
