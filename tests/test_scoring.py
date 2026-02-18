from static_analysis.static_runner import run_static_analysis
from scoring_engine.pbh_fingerprint import generate_pbh_fingerprint


def main():
    url = input("Enter URL: ")

    static_results = run_static_analysis(url)

    pbh = generate_pbh_fingerprint(static_results)

    print("\n=== PBH RESULT ===")
    print(pbh)


if __name__ == "__main__":
    main()
