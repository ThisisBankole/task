# Use an official Python runtime as the base image
FROM python:slim-bullseye


# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 5000 available to the world outside this container
EXPOSE 8000

# Define environment variable for Flask to run in production mode
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=production

# Run app.py when the container launches
CMD ["flask", "run", "--host=0.0.0.0", "--port=8000"]