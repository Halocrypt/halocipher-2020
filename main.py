"""
    Halocipher: Copyright 2020 (Utkarsh Dubey, Dhruv Bhatia)
    Halocipher was built for Halocrypt 2020, you can always use this commercially if you want to get hacked.
"""

# Imports
from functools import partial
from io import StringIO
import random, json


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
def encrypt(message):

    """
    Converting the text into a List() of chunks with the chunk_size = 10
    """

    # Lowercasing the message content
    block_string = u'{}'.format(message.lower())

    # Chunk Code
    chunk_size = 10
    chunks = [l for l in iter(partial(StringIO(block_string).read, chunk_size), '')]
    
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
        
        """
            Sorting: Randomly picking letters for encrypted/schema file.
            <Eg: _great --> (_gat),(re)
        """
        
         # Encrypted and Schema Blocks
        chunk_random_indices = random.sample(range(0, len(chunk)), random.randint(0, len(chunk)))

        if not chunk_random_indices:
            chunk_random_indices.append(0)

        if len(chunk_random_indices) == len(chunk):
            chunk_random_indices = random.sample(range(0, len(chunk)), random.randint(0, len(chunk)))

        chunk_encrypted = {}
        chunk_schema = {}


        for indice in chunk_dict:
            if int(indice) in chunk_random_indices:
                chunk_encrypted[str(indice)] = chunk_dict.get(indice)
            else:
                chunk_schema[str(indice)] = chunk_dict.get(indice)

        if not chunk_schema:
            chunk_schema["0"] = chunk_dict.get("0")

        if not chunk_encrypted:
            chunk_encrypted["0"] = chunk_dict.get("0")

        block["encrypted"] = chunk_encrypted
        block["schema"] = chunk_schema



        blocks.append(block)
        signature_count += signature_increment


        
    return blocks

print(json.dumps(encrypt("Twenty One Pilots is great"), indent=4))