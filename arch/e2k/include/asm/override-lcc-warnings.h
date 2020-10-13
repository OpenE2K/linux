/* type qualifiers are meaningless in this declaration */
#pragma diag_suppress 21

/* integer conversion resulted in truncation */
#pragma diag_suppress 69

/* this declaration has no storage class or type specifier */
#pragma diag_suppress 77

/* identifier-list parameters may only be used in a function definition */
#pragma diag_suppress 92

/* signed bit field of length 1 */
#pragma diag_suppress 108

/* expression has no effect */
#pragma diag_suppress 174

//TODO bug 53023
/* use of "=" where "==" may have been intended */
#pragma diag_suppress 187

/* controlling expression is constant */
#pragma diag_suppress 236

/* variable-length array field type will be treated
 * as zero-length array field type */
#pragma diag_suppress 1155

/* result of call is not used */
//TODO bug 53360
#pragma diag_suppress 1650
