import ast
import operator

# ==========================
# SECURE ENGINE DEFINITION
# ==========================

# 1. Map AST nodes to safe, native Python operators
ALLOWED_OPERATORS = {
    ast.Add: operator.add,       # +
    ast.Sub: operator.sub,       # -
    ast.Mult: operator.mul,      # *
    ast.Div: operator.truediv,   # /
    ast.Pow: operator.pow,       # ** (Exponent)
    ast.USub: operator.neg,      # Unary minus (e.g., -5)
    ast.UAdd: operator.pos       # Unary plus (e.g., +5)
}

def secure_eval(expr_str):
    """
    Parses and evaluates mathematical expressions securely using an Abstract Syntax Tree (AST).
    Does not use Python's unsafe built-in eval().
    """
    if not expr_str.strip():
        return ""

    try:
        # Parse the string into an AST tree expression mode
        tree = ast.parse(expr_str, mode='eval')
        
        # Evaluate the abstract syntax tree recursively
        return _eval_node(tree.body)
        
    except SyntaxError:
        return "Error: Invalid syntax."
    except ZeroDivisionError:
        return "Error: Division by zero."
    except OverflowError:
        return "Error: Number too large."
    except Exception as e:
        return f"Error: {str(e)}"

def _eval_node(node):
    """
    Walks through approved nodes recursively.
    If it finds any unapproved node (like a function call, string manipulation, or class definition),
    it immediately triggers an exception.
    """
    # Base case: The node is a raw number (Literal)
    if isinstance(node, ast.Constant): 
        if isinstance(node.value, (int, float)):
            return node.value
        raise TypeError("Only numbers are allowed.")

    # Case: Binary Operations (e.g., Left + Right)
    elif isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type in ALLOWED_OPERATORS:
            left_val = _eval_node(node.left)
            right_val = _eval_node(node.right)
            return ALLOWED_OPERATORS[op_type](left_val, right_val)
        raise NotImplementedError(f"Operator '{op_type.__name__}' is blocked.")

    # Case: Unary Operations (e.g., -5 or +5)
    elif isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type in ALLOWED_OPERATORS:
            operand_val = _eval_node(node.operand)
            return ALLOWED_OPERATORS[op_type](operand_val)
        raise NotImplementedError(f"Unary operator '{op_type.__name__}' is blocked.")

    # Anything else (Variables, Function Calls, Imports, Loops) is malicious or unapproved
    else:
        raise ValueError("Malicious or unsupported syntax detected.")


# ==========================
# TERMINAL INTERFACE
# ==========================

def run_calculator():
    print("=========================================")
    print(" Secure AST Mathematical Evaluator       ")
    print("=========================================")
    print("Supports: +, -, *, /, ** (power), and ( )")
    print("Type 'exit' or 'quit' to close.\n")

    while True:
        try:
            cmd = input("calc:~$ ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break

        if not cmd:
            continue

        if cmd.lower() in ("exit", "quit"):
            break

        if cmd.lower() in ("clear", "cls"):
            print("\n" * 50)
            continue

        # Process the input securely
        result = secure_eval(cmd)
        
        print("━━━━━━━━━━━━━━━━━━━━━━")
        print(f"Result: {result}")
        print("━━━━━━━━━━━━━━━━━━━━━━\n")

if __name__ == "__main__":
    run_calculator()