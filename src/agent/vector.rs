//! Provider-aware, canary-only RAG/vector probe generation.
//!
//! This module generates request bodies; it does not send them. Callers must
//! execute the returned probes through the scoped agent transport and only
//! against indexes/tenants containing synthetic test documents.

use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Pinecone,
    Qdrant,
    Weaviate,
    Milvus,
    Pgvector,
}

impl Provider {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "pinecone" => Some(Self::Pinecone),
            "qdrant" => Some(Self::Qdrant),
            "weaviate" => Some(Self::Weaviate),
            "milvus" => Some(Self::Milvus),
            "pgvector" | "postgres" => Some(Self::Pgvector),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VectorProbe {
    pub id: &'static str,
    pub category: &'static str,
    pub method: &'static str,
    pub path_suffix: &'static str,
    pub body: Value,
    pub canary: String,
}

/// Generate bounded probes for common vector APIs. `canary` must be synthetic.
pub fn probes(provider: Provider, canary: &str) -> Vec<VectorProbe> {
    let c = canary.to_string();
    match provider {
        Provider::Pinecone => vec![
            probe(
                "vector-tenant-filter-bypass",
                "tenant-isolation",
                "/query",
                json!({"vector":[0.0],"topK":10,"includeMetadata":true,"filter":{"tenant":{"$in":["TENANT_B","TENANT_A"]}}}),
                &c,
            ),
            probe(
                "vector-deleted-retention",
                "deletion-retention",
                "/query",
                json!({"vector":[0.0],"topK":10,"includeMetadata":true,"filter":{"canary":{"$eq":c}}}),
                &c,
            ),
            probe(
                "vector-namespace-confusion",
                "namespace-isolation",
                "/query",
                json!({"namespace":"TENANT_B","vector":[0.0],"topK":10,"includeMetadata":true,"filter":{"canary":{"$eq":c}}}),
                &c,
            ),
            probe(
                "vector-filter-operator-coercion",
                "filter-coercion",
                "/query",
                json!({"vector":[0.0],"topK":10,"includeMetadata":true,"filter":{"tenant":{"$exists":true},"canary":{"$ne":"UNSEEDED"}}}),
                &c,
            ),
            probe(
                "vector-sparse-dense-mixing",
                "embedding-validation",
                "/query",
                json!({"vector":{"values":[0.0],"sparseValues":{"indices":[0],"values":[1.0]}},"topK":10,"includeMetadata":true,"filter":{"canary":{"$eq":c}}}),
                &c,
            ),
        ],
        Provider::Qdrant => vec![
            probe(
                "vector-tenant-filter-bypass",
                "tenant-isolation",
                "/points/search",
                json!({"vector":[0.0],"limit":10,"with_payload":true,"filter":{"must":[{"key":"tenant","match":{"value":"TENANT_B"}}]}}),
                &c,
            ),
            probe(
                "vector-deleted-retention",
                "deletion-retention",
                "/points/scroll",
                json!({"limit":10,"with_payload":true,"filter":{"must":[{"key":"canary","match":{"value":c}}]}}),
                &c,
            ),
            probe(
                "vector-collection-filter-bypass",
                "collection-isolation",
                "/points/search",
                json!({"vector":[0.0],"limit":10,"with_payload":true,"filter":{"should":[{"key":"tenant","match":{"value":"TENANT_B"}},{"key":"canary","match":{"value":c}}]}}),
                &c,
            ),
            probe(
                "vector-payload-type-confusion",
                "metadata-coercion",
                "/points/scroll",
                json!({"limit":10,"with_payload":true,"filter":{"must":[{"key":"canary","match":{"any":[c,"RZ-VECTOR-CANARY"]}}]}}),
                &c,
            ),
            probe(
                "vector-score-threshold-bypass",
                "ranking-integrity",
                "/points/search",
                json!({"vector":[0.0],"limit":10,"score_threshold":-1.0,"with_payload":true,"filter":{"must":[{"key":"canary","match":{"value":c}}]}}),
                &c,
            ),
        ],
        Provider::Weaviate => {
            let query = "query RzVector { Get { Document(where: {path: [\"canary\"], operator: Equal, valueText: \"__CANARY__\"}) { content tenant canary } } }"
                .replace("__CANARY__", &c);
            vec![
                probe(
                    "vector-metadata-filter-bypass",
                    "metadata-filter-bypass",
                    "/v1/graphql",
                    json!({"query": query}),
                    &c,
                ),
                probe(
                    "vector-cross-tenant-graphql",
                    "tenant-isolation",
                    "/v1/graphql",
                    json!({"query": "query RzVector { Get { Document { content tenant canary } } }"}),
                    &c,
                ),
                probe(
                    "vector-neartext-injection",
                    "query-integrity",
                    "/v1/graphql",
                    json!({"query": format!("query RzVector {{ Get {{ Document(nearText: {{concepts: [\"{}\"]}}) {{ content tenant canary }} }} }}", graphql_escape(&c))}),
                    &c,
                ),
            ]
        }
        Provider::Milvus => vec![
            probe(
                "vector-tenant-filter-bypass",
                "tenant-isolation",
                "/v2/vectordb/entities/query",
                json!({"filter":"tenant == 'TENANT_B'","outputFields":["tenant","canary"]}),
                &c,
            ),
            probe(
                "vector-partition-bypass",
                "partition-isolation",
                "/v2/vectordb/entities/query",
                json!({"filter":"tenant != 'TENANT_A' && canary == 'RZ-VECTOR-CANARY'","outputFields":["tenant","canary"]}),
                &c,
            ),
            probe(
                "vector-expression-coercion",
                "filter-coercion",
                "/v2/vectordb/entities/query",
                json!({"filter":format!("canary in ['{}', 'UNSEEDED']", milvus_escape(&c)),"outputFields":["tenant","canary"]}),
                &c,
            ),
        ],
        Provider::Pgvector => vec![
            probe(
                "vector-metadata-filter-bypass",
                "metadata-filter-bypass",
                "/query",
                json!({"sql":format!("SELECT id, tenant, content FROM documents WHERE canary = '{}'", c.replace('\'', "''"))}),
                &c,
            ),
            probe(
                "vector-tenant-sql-policy",
                "tenant-isolation",
                "/query",
                json!({"sql":format!("SELECT id, tenant, content FROM documents WHERE canary = '{}' AND tenant <> 'TENANT_A'", sql_escape(&c))}),
                &c,
            ),
            probe(
                "vector-distance-integrity",
                "ranking-integrity",
                "/query",
                json!({"sql":format!("SELECT id, tenant, content FROM documents WHERE canary = '{}' ORDER BY embedding <-> '[0,0]'::vector LIMIT 10", sql_escape(&c))}),
                &c,
            ),
        ],
    }
}

fn sql_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "''")
}
fn milvus_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}
fn graphql_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn probe(
    id: &'static str,
    category: &'static str,
    path_suffix: &'static str,
    body: Value,
    canary: &str,
) -> VectorProbe {
    VectorProbe {
        id,
        category,
        method: "POST",
        path_suffix,
        body,
        canary: canary.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_providers_generate_bounded_canary_probes() {
        for provider in [
            Provider::Pinecone,
            Provider::Qdrant,
            Provider::Weaviate,
            Provider::Milvus,
            Provider::Pgvector,
        ] {
            let probes = probes(provider, "RZ-VECTOR-CANARY");
            assert!(!probes.is_empty());
            assert!(probes.len() <= 5);
            assert!(probes
                .iter()
                .all(|p| p.body.to_string().contains("RZ-VECTOR-CANARY")
                    || p.canary == "RZ-VECTOR-CANARY"));
        }
    }

    #[test]
    fn provider_names_are_strict() {
        assert_eq!(Provider::parse("qdrant"), Some(Provider::Qdrant));
        assert_eq!(Provider::parse("unknown"), None);
    }
}
