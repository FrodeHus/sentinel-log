FROM python:3.9-slim
ENV UNIFI_USERNAME=dummy
ENV UNIFI_PASSWORD=dummypass
ENV UNIFI_CONTROLLER=127.0.0.1
ENV AZURE_STORAGE_CONNECTION_STRING=dummyconnection
RUN useradd --no-create-home --shell /bin/bash threatupdater 
WORKDIR /threatupdater
ADD update-block-list.py .
ADD requirements.txt .
RUN pip install -r requirements.txt
USER threatupdater
CMD ["python", "update-block-list.py"]
