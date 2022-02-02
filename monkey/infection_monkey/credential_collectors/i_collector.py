import abc


class ICollector(metaclass=abc.ABCMeta):
    @staticmethod
    @abc.abstractmethod
    def collect():
        pass
