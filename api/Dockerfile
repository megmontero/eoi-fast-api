FROM python:3.12-slim
WORKDIR /code
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . /code 
EXPOSE 4242
ENV TZ="Europe/Madrid"
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "4242", "--reload"]
