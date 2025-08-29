# Ghidra Headless and Marimo

This project provides a Docker-based environment for reverse engineering and vulnerability research. It combines Ghidra, a software reverse engineering framework, with Marimo, allowing for interactive analysis and visualization of binaries.

## Building and Running

The project is designed to be run within a Docker container.

### Build the Docker Image

To build the Docker image, run the following command in the project's root directory:

```bash
docker build -t headless .
```

For Apple Silicon, you may need to use the following command:

```bash
docker build -t headless . --platform=linux/amd64 --no-cache
```

### Run the Docker Container

To run the Docker container, use the following command:

```bash
docker run -p 2718:2718 -it -v ${PWD}:/local headless
```

This will start a Marimo server on port 2718. You can access it by navigating to `http://localhost:2718` in your web browser.

## Included Notebooks

The project includes two example notebooks:

- **Capa.py**: Demonstrates how to use Capa to identify the capabilities of a program.
- **PyGhidra.py**: Shows how to use PyGhidra to script Ghidra for automated analysis.

## Development

Users are encouraged to create their own Marimo notebooks to experiment with the environment. The notebooks are located in the `/local` directory inside the container, which is mapped to the project's root directory on the host machine.
