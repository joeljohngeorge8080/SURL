from static_analysis.static_runner import run_static_analysis
from scoring_engine.score_calculator import calculate_risk_score


url = input("Enter URL: ")
static_results = run_static_analysis(url)

final_result = calculate_risk_score(static_results)

print("\n=== FINAL RISK REPORT ===")
print(final_result)
