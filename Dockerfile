# Use the official Python base image
FROM python:3.9

# Set the working directory inside the container
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the source code
COPY . .

# Expose the port on which the FastAPI server will run (if needed)
EXPOSE 9001

# Default environment to "DEVELOPMENT" during the build process
ARG ENV=DEVELOPMENT
ENV ENV=$ENV

# Start the FastAPI application using Uvicorn
CMD ["python", "main.py"]
