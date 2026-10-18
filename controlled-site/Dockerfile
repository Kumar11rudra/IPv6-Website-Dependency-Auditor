FROM python:3.12-slim

# Phase 9 hardening: run as a dedicated non-root user rather than the image default
# (root). Binding to ports 80/443 still works despite being non-root because
# docker-compose.yml grants exactly the one capability that requires
# (CAP_NET_BIND_SERVICE) to each service that needs it, rather than running the whole
# container as root to get it.
RUN useradd --create-home --shell /usr/sbin/nologin appuser

WORKDIR /site
COPY content ./content
COPY server ./server
COPY seeded.json .
RUN chown -R appuser:appuser /site
USER appuser
