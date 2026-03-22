"""Setup configuration for the Prompt Injection Toolkit."""

from pathlib import Path

from setuptools import find_packages, setup

long_description = Path("README.md").read_text(encoding="utf-8")

setup(
    name="prompt-injection-toolkit",
    version="0.1.0",
    author="Abdelkader Benmeriem",
    author_email="abdelkader.benmeriem@example.com",
    description=(
        "A comprehensive framework for testing LLM applications "
        "against prompt injection attacks."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kadirou12333/prompt-injection-toolkit",
    project_urls={
        "Bug Tracker": "https://github.com/kadirou12333/prompt-injection-toolkit/issues",
        "Documentation": "https://github.com/kadirou12333/prompt-injection-toolkit#readme",
        "Source Code": "https://github.com/kadirou12333/prompt-injection-toolkit",
    },
    packages=find_packages(exclude=["tests*", "examples*"]),
    package_data={
        "pit": ["payloads/data/*.json"],
    },
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "openai>=1.0.0",
        "anthropic>=0.18.0",
        "httpx>=0.25.0",
        "rich>=13.0.0",
        "pydantic>=2.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "ruff>=0.1.0",
            "mypy>=1.0.0",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
    ],
    keywords=[
        "prompt-injection",
        "llm-security",
        "ai-red-team",
        "ai-safety",
        "security-testing",
        "llm",
    ],
)
