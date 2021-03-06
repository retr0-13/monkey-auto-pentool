from abc import ABC, abstractmethod
from typing import Any


class IEncryptor(ABC):
    @abstractmethod
    def encrypt(self, plaintext: Any) -> Any:
        """Encrypts data and returns the ciphertext.
        :param plaintext: Data that will be encrypted
        :return: Ciphertext generated by encrypting value
        :rtype: Any
        """

    @abstractmethod
    def decrypt(self, ciphertext: Any):
        """Decrypts data and returns the plaintext.
        :param ciphertext: Ciphertext that will be decrypted
        :return: Plaintext generated by decrypting value
        :rtype: Any
        """
