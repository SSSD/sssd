from enum import Enum

from abc import ABC, abstractmethod


class Reader(ABC):
    """
    An abstract class used to represent a source Reader
    """

    class Component(Enum):
        """ SSSD component to enable for reading """
        NSS = 1   # NSS Responder
        PAM = 2   # PAM Responder
        BE = 3    # Backend

    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def __iter__(self):
        pass

    @abstractmethod
    def set_component(self):
        pass
