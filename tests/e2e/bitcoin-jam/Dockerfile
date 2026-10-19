# Reference JAM needs legacy BDB wallets, which newer Core majors removed.
FROM bitcoin/bitcoin:28

# Seed only new volumes at build time. Never repair or chown persisted data at startup.
RUN mkdir -p /data/.bitcoin && chown 1000:1000 /data /data/.bitcoin
ENV HOME=/data BITCOIN_DATA=/data/.bitcoin
VOLUME /data/.bitcoin
USER 1000:1000
ENTRYPOINT ["bitcoind"]
CMD ["-datadir=/data/.bitcoin"]
