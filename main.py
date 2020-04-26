"""
    Halocipher: Copyright 2020 (Utkarsh Dubey, Dhruv Bhatia)

    Halocipher was built for Halocrypt 2020, you can always use this commercially if you want to get hacked.

"""

# Imports
from functools import partial
from io import StringIO
import random


"""
    Utility Classes
"""
class File():
    def __init__(self, content, filename, extension):
        self.content = content
        self.filename = filename
        self.extension = extension

    def save(self):
        with open(str(self.filename + "." + self.extension), 'w', encoding='utf-8') as file:
            file.write(self.content)
            file.close()

"""
    Encrypt/Decrypt Functions

"""
def encrypt(message: str):

    """
    Converting the text into a List() of chunks with the chunk_size = 10
    """

    # Lowercasing the message content
    block_string = message.lower()

    # Chunk Code
    chunk_size = 10
    chunks = [l for l in iter(partial(StringIO(message).read, chunk_size), '')]
    
    """
    Converting chunks into Blocks :-->
    Adding a predecided signature that increments with +10 to the chunks respectively
    """

    # An empty list that will contain blocks
    blocks = []

    # The signature counter, default: 0
    signature_count = 0

    # The signature increment value, default: 10
    signature_increment = 10

    # Looping through the chunks and appending them to the block <List>
    for chunk in chunks:
        block = {}
        
        # Temporary dictionary for holding the chunk dictionary <Eg: {0: 'T', 1: 'w', ...}
        chunk_dict = {}


        # Looping through the letter in the chunk and appending them to the dictionary
        for index, letter in enumerate(chunk):
            chunk_dict[index] = letter

        block["signature"] = signature_count
        block["chunk"] = chunk_dict
        block["encrypted"] = random.sample(list(chunk_dict.fromkeys(range(100))), 10)

        blocks.append(block)
        signature_count += signature_increment

    """
    Sorting: Randomly picking letters for encrypted/schema file.
    <Eg: _great --> (_gat),(re)

    """
        
    return blocks

print(encrypt("Twenty One Pilots is great"))
