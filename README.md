# tidestide
A trial work of Attribute-based access control lib


## Introdution


This is a trial project attempting to implement a Attribute-based access control library.

The main design strategy is to use bitmap and flattened tree data to fast calculate authorization.

This project is not accomplished and is based on the flask framework for trial, but is aimed to work independently.


## Usage:

### 1. Collect resources via decorator

```python

@auth_check(
    filters=Filters(
        ("Owner", DB_MODEL.owner, attrgetter("id")),
        ("Deleted", DB_MODEL.is_del, [("deleted", 0), ("notdel", 1)]),
    )
)
def view_function(self):
    # Biz code
    return data
```
The `auth_check` decorator will automatically collect this view function as a resource entity, for more fine-grained auth control, we can use the `Filters` class to define more filtering details.

When a web request comes to the `view_function`, the `auth_check` decorator will check the user's authorization with rules.

### 2. Add other type resources

### 3. Add attributes and rules

