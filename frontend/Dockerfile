FROM python:3.9
WORKDIR /usr/src/app
COPY requirements.txt ./requirements.txt

# install system dependencies
RUN apt-get update \
  && apt-get -y install netcat gcc \
  && apt-get clean

# install python dependencies
RUN pip install --upgrade pip

RUN pip3 install -r requirements.txt
COPY . .