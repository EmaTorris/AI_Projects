from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate


llm = OllamaLLM(model="llama3:8b")

prompt = PromptTemplate(
    input_variables=["query", "cve_context"],
    template="""
    Sei un esperto di cybersecurity. 
    Un utente ha cercato vulnerabilità relative a: {query}
    
    Queste sono le vulnerabilità trovate nel database:
    {cve_context}
    
    Fornisci:
    1. Una spiegazione chiara delle vulnerabilità trovate
    2. Il livello di rischio complessivo
    3. I remediation steps consigliati
    
    Rispondi in italiano in modo chiaro e professionale.
    """
     )

def explain_cve(query_text: str,cve_list: list[dict]) -> str:
    cve_context = ""
    for cve in cve_list:
        cve_context += f"""
            CVE ID: {cve['cve_id']}
            Descrizione: {cve['description']}
            Severity: {cve['severity']}
            CVSS Score: {cve['cvss_metrics']}
            ---
            """

    chain = prompt | llm

    result = chain.invoke({
        "query": query_text,
        "cve_context": cve_context
    })

    return result