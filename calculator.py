import ast
import operator
import math
from decimal import Decimal, ROUND_HALF_UP

# ==========================
# SECURE ENGINE DEFINITION
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

def secure_eval(expr_str):
    if not expr_str.strip(): return ""
    try:
        tree = ast.parse(expr_str, mode='eval')
        raw_result = _eval_node(tree.body)
        return Decimal(str(raw_result)).quantize(PRECISION, rounding=ROUND_HALF_UP)
    except Exception as e:
        return f"Error: {e}"

def _eval_node(node):
    if isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Name):
        if node.id in ALLOWED_CONSTANTS:
            return ALLOWED_CONSTANTS[node.id]
        raise ValueError(f"Unknown constant: {node.id}")
    elif isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in ALLOWED_FUNCS:
            return ALLOWED_FUNCS[node.func.id](_eval_node(node.args[0]))
        raise ValueError(f"Function {node.func.id} not allowed.")
    elif isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type in ALLOWED_OPERATORS:
            return ALLOWED_OPERATORS[op_type](_eval_node(node.left), _eval_node(node.right))
        raise NotImplementedError(f"Operator '{op_type.__name__}' is blocked.")
    elif isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type in ALLOWED_OPERATORS:
            return ALLOWED_OPERATORS[op_type](_eval_node(node.operand))
        raise NotImplementedError(f"Unary operator '{op_type.__name__}' is blocked.")
    else:
        raise ValueError("Malicious or unsupported syntax detected.")

# ==========================
# TERMINAL INTERFACE
# ==========================

def run_calculator():
    print("=========================================")
    print(" Secure AST Mathematical Evaluator       ")
    print("=========================================")
    print("Supports: +, -, *, /, **, sqrt(), cbrt(), pi")
    print("Type 'exit' or 'quit' to close.\n")

    while True:
        try:
            cmd = input("calc:~$ ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break

        if not cmd: continue
        if cmd.lower() in ("exit", "quit"): break
        if cmd.lower() in ("clear", "cls"):
            print("\n" * 50); continue

        result = secure_eval(cmd)
        print("━━━━━━━━━━━━━━━━━━━━━━")
        print(f"Result: {result}")
        print("━━━━━━━━━━━━━━━━━━━━━━\n")

if __name__ == "__main__":
    run_calculator()
