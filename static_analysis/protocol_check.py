import re

def http_checker(link):
    """
    Checks whether the URL uses HTTPS.
    Returns a signal instead of printing.
    """
    result = re.search(r"^https://", link)

    if result is None:
        return {
            "uses_https": False,
            "note": "URL does not use HTTPS"
        }
    else:
        return {
            "uses_https": True,
            "note": "URL uses HTTPS"
        }


#      testing
#      this should be used for testing
# user = input("Paste your link: ")
# print(http_checker(user))
