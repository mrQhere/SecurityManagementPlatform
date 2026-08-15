from typing import List, Dict

class RetryHandler:
    def __init__(self, policy: Dict):
        self.policy = policy
        self.attempt_count = 0
        self.max_retries = policy.get("max_retries", 3)
        self.retryable_errors = set(policy.get("retryable_errors", []))
        self.non_retryable_errors = set(policy.get("non_retryable_errors", []))
        self.backoff_strategy = policy.get("backoff_strategy", "exponential")
        self.initial_delay = policy.get("initial_delay", 2)
        self.max_delay = policy.get("max_delay", 60)
    
    def should_retry(self, error: str, exit_code: int) -> bool:
        """Determine if error is retryable."""
        if self.attempt_count >= self.max_retries:
            return False
            
        if error in self.non_retryable_errors:
            return False
            
        # Specific retryable conditions
        if error in self.retryable_errors:
            return True
            
        # By default, don't retry if exit code is successful
        if exit_code == 0:
            return False
            
        # Default behavior for unknown errors (could be configured)
        return True
    
    def get_delay(self) -> int:
        """Calculate retry delay based on strategy."""
        if self.backoff_strategy == "exponential":
            delay = self.initial_delay * (2 ** self.attempt_count)
        elif self.backoff_strategy == "linear":
            delay = self.initial_delay * (self.attempt_count + 1)
        else: # fixed
            delay = self.initial_delay
            
        return min(delay, self.max_delay)
    
    def record_attempt(self, success: bool):
        """Record retry attempt."""
        if not success:
            self.attempt_count += 1
