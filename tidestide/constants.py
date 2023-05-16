from enum import IntEnum


class AuthResourcesType(IntEnum):
    """Enumeration for authority resource types."""

    DOM = 1  # Front-end DOM
    API = 2  # Back-end API
    DATA = 4  # Database column filter
    DATA_RUN = 5  # Runtime calulated filter
    DATA_FILTER = 6  # Database columns filter values