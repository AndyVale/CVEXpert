import trafilatura

def extract_main_text_from_url(url: str) -> str:
    """
    Fetch a URL and extract only the main meaningful text content.
    Returns "" if the URL is unreachable or any error occurs.
    """
    try:
        downloaded = trafilatura.fetch_url(url)

        if downloaded is None:
            return ""

        # extract the main content
        text = trafilatura.extract(downloaded)
        if text is None:
            return ""

        # collapse whitespace
        clean_text = " ".join(text.split())
        return clean_text

    except Exception as e:
        return ""


if __name__ == '__main__':
    with open("file.txt", "w") as f:
       f.write(extract_main_text_from_url("https://github.com/colorjs/color-name/security/advisories/GHSA-5fvm-p68v-5wmh"))