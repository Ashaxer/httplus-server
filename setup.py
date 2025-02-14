from setuptools import setup, find_packages

setup(
    name="httplus-server",
    version="0.1.3",
    author="Shaxius",
    author_email="hakramzade78@gmail.com",
    description="A multithreaded HTTP server with authentication and partial content support.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Ashaxer/httplus-server",
    packages=find_packages(),
    install_requires=[],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "httplus-server=httplus_server.server:main",
        ],
    },
    python_requires=">=3.6",
)
