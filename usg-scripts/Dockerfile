FROM python:3.9-slim
ENV UNIFI_USERNAME=dummy
ENV UNIFI_PASSWORD=dummypass
ENV UNIFI_CONTROLLER=127.0.0.1
ENV AZURE_STORAGE_CONNECTION_STRING=dummyconnection
ENV EVICT_AFTER_DAYS=7
# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE=1
# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1
RUN useradd --no-create-home --shell /bin/bash threatupdater 
WORKDIR /threatupdater
ADD requirements.txt .
RUN pip install -r requirements.txt
ADD update-block-list.py .
USER threatupdater
CMD ["python", "update-block-list.py"]
