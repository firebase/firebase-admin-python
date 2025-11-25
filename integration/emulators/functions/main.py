from firebase_functions import tasks_fn

@tasks_fn.on_task_dispatched()
def testTaskQueue(req: tasks_fn.CallableRequest) -> None:
    """Handles tasks from the task queue."""
    print(f"Received task with data: {req.data}")
    return