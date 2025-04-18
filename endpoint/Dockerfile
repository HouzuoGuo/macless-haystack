FROM python:slim

WORKDIR /app

RUN apt-get update && apt-get install -y curl nano iproute2 git cron
COPY ./ /app/
# Configure python
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt
CMD ["sh", "-c", "python mh_endpoint.py"]
