# scanner.py

from duckduckgo_search import DDGS

def find_footprint(query):
    """
    Searches DuckDuckGo for the user's input query and returns
    up to 10 structured search results including title, URL, and snippet.
    """
    results = []
    with DDGS() as ddgs:
        for i, result in enumerate(ddgs.text(keywords=query, max_results=10)):
            results.append({
                "id": f"duck_{i}",  # unique ID for each result
                "title": result.get("title", "No Title"),
                "url": result.get("href", "#"),
                "snippet": result.get("body", "")
            })
    return results
