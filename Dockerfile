FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

LABEL org.opencontainers.image.title="DAH Team 9 Defender" \
      org.opencontainers.image.description="Standard-library-only defensive packet agent"

WORKDIR /app

COPY defender.py detectors.py rehearsal_web_detectors.py protocol_profiles.py signatures.py ./

RUN dpkg-query -W -f='${binary:Package}\t${Version}\n' > /app/system-packages.tsv \
 && python -m pip list --format=json > /app/python-packages.json

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 65534:65534

ENTRYPOINT ["python", "/app/defender.py"]
