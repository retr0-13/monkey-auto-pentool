from dataclasses import dataclass


@dataclass
class Credentials:
    type: str
    data: dict

    def serialize(self) -> dict:
        return self.__dict__
