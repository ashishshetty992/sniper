import uvicorn
import multiprocessing
from app import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    uvicorn.run("app.main:app", host="localhost", port=9001, reload=True)