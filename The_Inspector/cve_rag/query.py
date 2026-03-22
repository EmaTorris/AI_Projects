from cve_rag.indexer import get_collection


def query_cve(query : str, n_results: int = 5) -> list[dict]:
    collection = get_collection()
    res = collection.query(
        query_texts=[query],
        n_results=n_results,
    )

    cve_results = []

    for id, docs, metadata, distance in zip(
        res["ids"][0],
        res["documents"][0],
        res["metadatas"][0],
        res["distances"][0]
    ):
        cve_results.append({
            "cve_id": id,
            "description": docs,
            "published_date": metadata["published_date"],
            "last_modified_date": metadata["last_modified_date"],
            "cvss_metrics": metadata["cvss_metrics"],
            "severity": metadata["severity"],
            "vuln_status": metadata["vuln_status"],
            "distance": distance
        })

    return cve_results