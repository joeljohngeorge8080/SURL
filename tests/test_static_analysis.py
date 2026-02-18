from app.services.scan_orchestrator import scan_url
import json


def main():
    url = input("Enter URL: ")
    result = scan_url(url)

    

    print("\n=== FINAL REPORT ===")
    print(json.dumps(result, indent=4, sort_keys=True))



if __name__ == "__main__":
    main()
