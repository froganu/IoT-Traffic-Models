"""
Setup script for MoE IoT C2 Detection System.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="moe-iot-c2-detection",
    version="0.1.0",
    description="Mixture of Experts System for IoT C2 Traffic Detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="MoE Team",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    install_requires=[
        "pandas>=1.3.0",
        "numpy>=1.21.0",
        "scikit-learn>=1.0.0",
    ],
    extras_require={
        "xgboost": ["xgboost>=1.5.0"],
        "tensorflow": ["tensorflow>=2.8.0", "keras>=2.8.0"],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "moe-detect=src.moe.integration:main",
            "encryption-detector=src.encryption_detector.cli:main",
        ],
    },
)

