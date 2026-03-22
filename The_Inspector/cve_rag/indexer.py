import chromadb
from chromadb.utils.embedding_functions import OllamaEmbeddingFunction


PATH = "./chroma_db"

#restituisce la collezione di ChromaDB
def get_collection():
    client = chromadb.PersistentClient(PATH)

    ef = OllamaEmbeddingFunction(
        model_name="embeddinggemma:latest",
        url="http://localhost:11434/api/embeddings",
    )

    collection = client.get_or_create_collection(name="cve_rag", embedding_function=ef)


    return collection

#indice i cve in ChromaDB
def index_cves(cve_list : list[dict]) -> None:
    collection = get_collection()

    ids = []
    documents = []
    metadatas = []

    for cve in cve_list:
        ids.append(cve["cve_id"])
        documents.append(cve["description"])
        metadatas.append({
            "published_date": cve["published_date"],
            "last_modified_date": cve["last_modified_date"],
            "cvss_metrics": cve["cvss_metrics"],
            "severity": cve["severity"],
            "vuln_status": cve["vuln_status"],
        })

    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)

    print(f"Indicizzati {len(ids)} CVE in ChromaDB")