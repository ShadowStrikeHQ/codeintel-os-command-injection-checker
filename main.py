import argparse
import subprocess
import logging
import os
import shlex
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Detects potential OS command injection vulnerabilities.')
    parser.add_argument('filepath', help='Path to the Python file to analyze.')
    parser.add_argument('--disable-bandit', action='store_true', help='Disable Bandit security linter.')
    parser.add_argument('--disable-flake8', action='store_true', help='Disable Flake8 style checker.')
    parser.add_argument('--disable-pylint', action='store_true', help='Disable Pylint code analyzer.')
    parser.add_argument('--disable-pyre', action='store_true', help='Disable Pyre-check static analyzer.')
    parser.add_argument('--output', '-o', help='Output file to save results.', default='output.txt')
    return parser

def is_command_injection_vulnerable(filepath):
    """
    Naive check for potential command injection vulnerabilities.
    This is a simplified check and may not catch all vulnerabilities.
    """
    try:
        with open(filepath, 'r') as f:
            code = f.read()
        
        if "os.system(" in code or "subprocess.call(" in code or "subprocess.Popen(" in code or "subprocess.run(" in code:
            if "input(" in code or "sys.argv[" in code or "os.environ[" in code:  # Check for user-supplied input
                logging.warning(f"Potential OS command injection vulnerability detected in {filepath}")
                return True
        return False
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return False
    except Exception as e:
        logging.error(f"Error during vulnerability check: {e}")
        return False


def run_bandit(filepath, output_file):
    """
    Runs Bandit security linter on the specified file.
    """
    try:
        command = f"bandit -r {filepath} -f txt -o {output_file}"
        logging.info(f"Running Bandit: {command}")
        result = subprocess.run(shlex.split(command), capture_output=True, text=True, check=True)
        logging.info(f"Bandit output:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Bandit failed with error: {e.stderr}")
    except Exception as e:
        logging.error(f"Error running Bandit: {e}")

def run_flake8(filepath, output_file):
    """
    Runs Flake8 style checker on the specified file.
    """
    try:
        command = f"flake8 {filepath} > {output_file}"
        logging.info(f"Running Flake8: {command}")
        result = subprocess.run(shlex.split(command), capture_output=True, text=True, check=False) #Non-zero exit code is ok
        logging.info(f"Flake8 output:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Flake8 failed with error: {e.stderr}")
    except Exception as e:
        logging.error(f"Error running Flake8: {e}")

def run_pylint(filepath, output_file):
    """
    Runs Pylint code analyzer on the specified file.
    """
    try:
        command = f"pylint {filepath} --output-format=text > {output_file}"
        logging.info(f"Running Pylint: {command}")
        result = subprocess.run(shlex.split(command), capture_output=True, text=True, check=False) #Non-zero exit code is ok
        logging.info(f"Pylint output:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Pylint failed with error: {e.stderr}")
    except Exception as e:
        logging.error(f"Error running Pylint: {e}")

def run_pyre(filepath):
    """
    Runs Pyre-check static analyzer on the specified file.
    """
    try:
        # Pyre requires a pyre_check config file or project setup
        # This is a placeholder and needs a proper Pyre setup
        logging.warning("Pyre integration is a placeholder and requires proper setup.")

        command = f"pyre analyze {filepath}"
        logging.info(f"Running Pyre: {command}")
        result = subprocess.run(shlex.split(command), capture_output=True, text=True, check=False) #Non-zero exit code is ok
        logging.info(f"Pyre output:\n{result.stdout}")


    except subprocess.CalledProcessError as e:
        logging.error(f"Pyre failed with error: {e.stderr}")
    except Exception as e:
        logging.error(f"Error running Pyre: {e}")


def main():
    """
    Main function to execute the code analysis.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    filepath = args.filepath
    output_file = args.output

    # Validate filepath
    if not os.path.isfile(filepath):
        logging.error(f"Invalid filepath: {filepath}. File does not exist.")
        sys.exit(1)
    
    # Perform command injection check
    if is_command_injection_vulnerable(filepath):
       print(f"Potential OS command injection vulnerability detected in {filepath}")
    else:
        print(f"No immediate OS command injection vulnerability detected in {filepath}")


    # Run static analysis tools based on user input
    if not args.disable_bandit:
        run_bandit(filepath, "bandit_output.txt")  # Save bandit output separately
    else:
        logging.info("Bandit is disabled.")

    if not args.disable_flake8:
        run_flake8(filepath, "flake8_output.txt")  # Save flake8 output separately
    else:
        logging.info("Flake8 is disabled.")

    if not args.disable_pylint:
        run_pylint(filepath, "pylint_output.txt") # Save pylint output separately
    else:
        logging.info("Pylint is disabled.")
    
    if not args.disable_pyre:
        run_pyre(filepath) #Pyre does not use output file
    else:
        logging.info("Pyre is disabled.")
    
    # Combine results into the output file
    try:
        with open(output_file, 'w') as outfile:
            if not args.disable_bandit and os.path.exists("bandit_output.txt"):
                with open("bandit_output.txt", 'r') as infile:
                    outfile.write("Bandit Output:\n")
                    outfile.write(infile.read())
                    outfile.write("\n\n")

            if not args.disable_flake8 and os.path.exists("flake8_output.txt"):
                with open("flake8_output.txt", 'r') as infile:
                    outfile.write("Flake8 Output:\n")
                    outfile.write(infile.read())
                    outfile.write("\n\n")

            if not args.disable_pylint and os.path.exists("pylint_output.txt"):
                with open("pylint_output.txt", 'r') as infile:
                    outfile.write("Pylint Output:\n")
                    outfile.write(infile.read())
                    outfile.write("\n\n")


        logging.info(f"Analysis complete. Results saved to {output_file}")
    except Exception as e:
        logging.error(f"Error combining results: {e}")


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Analyze a file: python main.py my_script.py
# 2. Disable Bandit: python main.py my_script.py --disable-bandit
# 3. Specify an output file: python main.py my_script.py -o results.txt
# 4. Disable all tools: python main.py my_script.py --disable-bandit --disable-flake8 --disable-pylint --disable-pyre