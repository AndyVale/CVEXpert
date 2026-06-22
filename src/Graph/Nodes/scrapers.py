import asyncio
import urllib.parse
from collections import defaultdict
import trafilatura
from tqdm.asyncio import tqdm as async_tqdm
from Graph.state import CVEClassifierState
from Definitions.config import REF_MAX

async def fetch_and_extract(url, origin_locks):
    origin = urllib.parse.urlparse(url).netloc
    
    # Wait for the lock for this specific origin to enforce rate limit
    async with origin_locks[origin]:
        try:
            # Run the blocking fetch in a separate thread
            downloaded = await asyncio.to_thread(trafilatura.fetch_url, url)
            if not downloaded:
                return url, None
            
            # Extract content in a thread
            text = await asyncio.to_thread(trafilatura.extract, downloaded, output_format="markdown", favor_recall=True)
            return url, text
        except Exception as e:
            print(f"Fail in extracting content of page at: {url}\n{e}")
            return url, None
        finally:
            # Enforce 2 second delay before the lock is released for the NEXT request to the same origin
            await asyncio.sleep(2.0)

async def async_extract_md_trafilatura(state: CVEClassifierState) -> CVEClassifierState:
    url_refs = state.get("nvd_url_references", []).copy()
    
    # Use asyncio.Lock per origin to ensure only one request per origin is active at a time
    # and the lock is held for 2 extra seconds after completion.
    origin_locks = defaultdict(asyncio.Lock)
    pages_dict = {}
    
    tasks = [asyncio.create_task(fetch_and_extract(url, origin_locks)) for url in url_refs]
    
    if not tasks:
        return {**state, "nvd_references_pages": pages_dict}
        
    for future in async_tqdm.as_completed(tasks, total=len(tasks), desc="Extracting references"):
        try:
            url, text = await future
            if text:
                pages_dict[url] = text
            if len(pages_dict) >= REF_MAX:
                for t in tasks:
                    t.cancel()
                break
        except Exception:
            pass
            
    return {**state, "nvd_references_pages": pages_dict}

def extract_md_trafilatura(state: CVEClassifierState) -> CVEClassifierState:
    """
    Fetches and extracts Markdown content from NVD reference URLs using Trafilatura.

    This function attempts to download and extract content in Markdown format concurrently
    using asyncio, enforcing a 2-second rate limit per origin to prevent being blocked.
    It processes up to REF_MAX successfully extracted pages.

    Args:
        state (CVEClassifierState): The current pipeline state containing 'nvd_url_references'.

    Returns:
        dict: A new state dictionary containing the extracted Markdown content.
    """
    return asyncio.run(async_extract_md_trafilatura(state))