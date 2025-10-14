from scipy.stats import norm


def required_sample_size(p, confidence_level=0.95, margin_of_error=0.04):
    """
    Calculate required sample size for estimating a proportion.

    Parameters:
        p (float): Expected true proportion (e.g., 0.3 for 30%)
        confidence_level (float): Desired confidence level (e.g., 0.95)
        margin_of_error (float): Desired margin of error (e.g., 0.04)

    Returns:
        float: Required sample size
    """
    # Significance level (alpha)
    alpha = 1 - confidence_level

    # Z critical value for two-tailed test
    z = norm.ppf(1 - alpha / 2)

    # Sample size formula
    n = (z ** 2 * p * (1 - p)) / (margin_of_error ** 2)

    return n

#
# # Example usage:
# p = 0.30
# confidence_level = 0.95
# margin_of_error = 0.04
# --- Read inputs ---
p = float(input("Enter the true conversion probability (e.g., 0.30): "))
confidence_level = float(input("Enter the desired confidence level (e.g., 0.95): "))
margin_of_error = float(input("Enter the desired margin of error (e.g., 0.04): "))


n = required_sample_size(p, confidence_level, margin_of_error)
print(f"Required sample size: {n:.2f}")
