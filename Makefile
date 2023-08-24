
default: ci

ci: prepare-pip
	@pytest s3mock_test.py

prepare-pip:
	@pip install -r requirements.txt
