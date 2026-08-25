FROM neo4j:5.26-community
COPY --chmod=0555 deploy/container/neo4j-entrypoint.sh /opt/watchtower/neo4j-entrypoint.sh
ENTRYPOINT ["/opt/watchtower/neo4j-entrypoint.sh"]
