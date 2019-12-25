# app.py or app/__init__.py

from Vinoth_Project import app
app.config.from_object('config')


if __name__ == '__main__':
    app.run()
# Now we can access the configuration variables via app.config["VAR_NAME"].
