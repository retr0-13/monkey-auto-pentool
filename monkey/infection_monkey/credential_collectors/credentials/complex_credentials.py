from dataclasses import dataclass


@dataclass
class ComplexCredentials:
    type: str
    data: dict

    def serialize(self):
        for cred in self.data:
            if "unserializable_value" in cred:
                cred["unserializable_value"] = True
        return self.__dict__
