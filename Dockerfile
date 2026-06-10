FROM python:3-alpine

LABEL org.opencontainers.image.title="VirusTotal Scanner Action"
LABEL org.opencontainers.image.description="Scan files with VirusTotal, view results directly in the job and automatically pass/fail based on the outcome"
LABEL org.opencontainers.image.source="https://github.com/jjw24/virustotal-scanner-action"
LABEL org.opencontainers.image.licenses="MIT"

COPY requirements.txt /action/requirements.txt
RUN pip install --no-cache-dir -r /action/requirements.txt

COPY virustotal_scan /action/virustotal_scan
COPY entrypoint.sh /action/entrypoint.sh
RUN chmod +x /action/entrypoint.sh
ENV PYTHONPATH=/action

WORKDIR /github/workspace
ENTRYPOINT ["/action/entrypoint.sh"]
