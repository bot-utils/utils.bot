FROM scratch
LABEL utils.bot.csv.private=true
# Supply the reviewed public CA bundle in this temporary build context.
COPY --chmod=0444 ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chmod=0555 csv-private-broker /csv-private-broker
USER 65532:65532
ENTRYPOINT ["/csv-private-broker"]
