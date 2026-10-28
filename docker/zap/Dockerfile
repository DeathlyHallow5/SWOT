FROM ghcr.io/zaproxy/zaproxy:stable
USER root
COPY server.py /opt/swot-zap/server.py
RUN mkdir -p /zap/wrk && chown -R zap:zap /zap/wrk /opt/swot-zap
USER zap
WORKDIR /zap/wrk
EXPOSE 8090
ENTRYPOINT []
CMD ["python3", "/opt/swot-zap/server.py"]
