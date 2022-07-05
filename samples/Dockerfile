FROM python:3

WORKDIR /home/app

COPY descope-auth-0.0.1.tar.gz /home/app

RUN pip3 install /home/app/descope-auth-0.0.1.tar.gz

ADD requirements.txt /home/app
RUN pip3 install -r requirements.txt

ADD . /home/app
CMD python3 otp_web_sample_app.py

EXPOSE 3000