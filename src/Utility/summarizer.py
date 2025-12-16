from ollama import Client

def summarize(text_to_summarize: str, model:str):
    """
    Summarize a NVD-CVE reference text, keeping only the core vulnerability information.
    The summary should focus on attack type, impact, affected components, root cause,
    and hints for classification labels. External links or irrelevant text are ignored.
    """
    
    prompt = f"""
You are a cybersecurity summarization assistant. You will receive text extracted from an external reference linked in the NVD (National Vulnerability Database). This text often contains a mix of useful security information and unrelated webpage content such as menus, advertisements, generic documentation, or unrelated GitHub material.

Your role is to distill only the parts that clearly describe a software vulnerability. The summary must focus on the essential technical elements: what type of vulnerability it is, what impact it has on systems or data, which components or versions are affected, and the underlying cause or mechanism that creates the issue. Include only what is stated in the text—avoid speculation, assumptions, or extrapolations.

The writing should be concise and human-readable, ideally limited to three to six sentences, with a neutral tone and no introductory phrases. The output should contain only the summary itself. Phrases such as “Here is the summary” or any other preamble must not appear. The result should be plain sentences, not lists or formatted blocks.

Below is the text extracted from the CVE reference:

{text_to_summarize}

If the provided text does not actually describe anthing realated to a vulnerability or realated things return an empty string instead of a summary.

Write only the summary, avoiding any introduction.
Give an empty string if the text does not describe a vulnerability or are related to it.

The summary:

"""
    c = Client()
    
    summarized_text = c.generate(model=model, prompt=prompt).response
    
    return summarized_text