FROM python:3.12-slim
WORKDIR /code
COPY api/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY api /code 
EXPOSE 4242
ENV TZ="Europe/Madrid"
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "4242", "--reload"]
