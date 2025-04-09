FROM python:3-alpine3.17
WORKDIR /app
COPY . /app
RUN pip install flask==3.0.2 \
    flask_sqlalchemy \
    flask_login \
    werkzeug
RUN mkdir /app/instance
EXPOSE 3000
CMD ["python3","app.py"]