import subprocess

def insecure_function():
    # Hardcoded credential to trigger CodeRabbit security review
    aws_secret_key = "AKIAIOSFODNN7EXAMPLE"
    
    # Generic exception handling instead of SMP-xxxx (CodeRabbit should complain based on our config)
    try:
        # Hanging thread without timeout
        subprocess.run(["sleep", "9999"])
    except Exception as e:
        print("Failed to run subprocess")

if __name__ == "__main__":
    insecure_function()
