from url_analyzer import analyze_urls


email = """
URGENT! Verify your account immediately.

Please login and confirm your password:

http://192.168.1.100/login
"""


results = analyze_urls(email)


print("=" * 50)
print("       ADVANCED URL SECURITY ANALYSIS")
print("=" * 50)


for result in results:

    print()
    print("URL:", result["url"])
    print("Domain:", result["domain"])
    print("Risk:", result["risk"])
    print("Score:", result["score"])

    print()
    print("Features:")

    for key, value in result["features"].items():
        print(" -", key, ":", value)

    print()
    print("Detection Reasons:")

    for reason in result["reasons"]:
        print(" -", reason)

    print()


print("=" * 50)