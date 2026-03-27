.PHONY: run install

install:
	python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt

run:
	source venv/bin/activate && python3 app.py
