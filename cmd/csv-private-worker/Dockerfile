# Build csv-private-worker as a static Linux ARM64 binary from the repository
# root, then use a temporary context containing that binary and this Dockerfile.
FROM scratch
LABEL utils.bot.csv.private=true
COPY --chmod=0555 csv-private-worker /csv-private-worker
USER 65533:65533
ENTRYPOINT ["/csv-private-worker"]
