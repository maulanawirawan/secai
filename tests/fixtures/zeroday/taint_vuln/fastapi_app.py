from fastapi import FastAPI

app = FastAPI()


@app.get("/items/{item_id}")
def read_item(item_id: int, q: str = ""):
    return {"id": item_id, "v": eval(q)}  # q is a query param (str)
