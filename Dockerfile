FROM python:3.9-slim

WORKDIR /app

COPY . .

# instala dependências e executa o setup.sh
RUN apt-get update && apt-get install -y openssl \
    && chmod +x setup.sh \
    && ./setup.sh

# instala as dependências do python
RUN pip install -r requirements.txt

# porta do servidor
EXPOSE 4443

# inicia o servidor
CMD ["python3", "src/server.py"]