import ast
import operator
import math
from decimal import Decimal, ROUND_HALF_UP

# ==========================
# CONFIGURATION
# ==========================
PRECISION = Decimal('0.00000001')

ALLOWED_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos
}

ALLOWED_FUNCS = {
    'sqrt': math.sqrt,
    'cbrt': lambda x: x**(1/3),
}

ALLOWED_CONSTANTS = {
    'pi': math.pi
}

# ==========================
# SECURE ENGINE
# ==========================

def secure_eval(expr_str):
    if not expr_str.strip(): return ""
    try:
        tree = ast.parse(expr_str, mode='eval')
        raw_result = _eval_node(tree.body)
        
        # Format to 8 decimal places
        return Decimal(str(raw_result)).quantize(PRECISION, rounding=ROUND_HALF_UP)
    except Exception as e:
        return f"Error: {e}"

def _eval_node(node):
    # Numbers
    if isinstance(node, ast.Constant):
        return node.value
    
    # Constants (pi)
    elif isinstance(node, ast.Name):
        if node.id in ALLOWED_CONSTANTS:
            return ALLOWED_CONSTANTS[node.id]
        raise ValueError(f"Unknown constant: {node.id}")
        
    # Functions (sqrt, cbrt)
    elif isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in ALLOWED_FUNCS:
            arg_val = _eval_node(node.args[0])
            return ALLOWED_FUNCS[node.func.id](arg_val)
        raise ValueError(f"Function {node.func.id} not allowed.")
        
    # Binary Ops (+, -, *, /, **)
    elif isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type in ALLOWED_OPERATORS:
            return ALLOWED_OPERATORS[op_type](_eval_node(node.left), _eval_node(node.right))
        raise NotImplementedError(f"Operator blocked.")

    # Unary Ops (-5)
    elif isinstance(node, ast.UnaryOp):
        return ALLOWED_OPERATORS[type(node.op)](_eval_node(node.operand))
        
    raise ValueError("Syntax not supported.")

# ==========================
# INTERFACE
# ==========================

def run_calculator():
    print("=== Secure Scientific Calculator (8-Digit Precision) ===")
    print("Supports: +, -, *, /, **, sqrt(), cbrt(), pi")
    while True:
        try:
            cmd = input("calc:~$ ").strip()
            if cmd.lower() in ("exit", "quit"): break
            if cmd.lower() in ("clear", "cls"): 
                print("\n" * 50); continue
            
            print(f"Result: {secure_eval(cmd)}")
        except EOFError: break

if __name__ == "__main__":
    run_calculator()
