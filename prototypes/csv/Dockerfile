FROM scratch
ENV PATH=/nonexistent
COPY --chmod=0555 bootstrap /csv-prototype
USER 65532:65532
ENTRYPOINT ["/csv-prototype"]
