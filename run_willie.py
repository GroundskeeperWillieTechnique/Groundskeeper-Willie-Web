import sys
import os

# Add the project root directory to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Also add 'src' directory explicitly
src_dir = os.path.join(current_dir, 'src')
sys.path.insert(0, src_dir)

if __name__ == '__main__':
    try:
        # standard import attempt
        from tools.willie_console import cli
        cli()
    except ImportError:
        try:
            # fallback if src is not in path correctly
            from src.tools.willie_console import cli
            cli()
        except ImportError as e:
            print(f"CRITICAL ERROR: Could not launch Willie.")
            print(f"Details: {e}")
            print(f"Sys Path: {sys.path}")
            sys.exit(1)
