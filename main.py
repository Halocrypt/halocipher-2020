"""
    Halocipher: Copyright 2020 (Utkarsh Dubey, Dhruv Bhatia)
    Halocipher was built for Halocrypt 2020, you can always use this commercially if you want to get hacked.
"""

# Imports
from functools import partial
from io import StringIO
import random, json, operator, string, re, sys
from collections import OrderedDict


"""

    RegEx for DECRYPTION  

"""

DECRYPTION_REGEX = r'<([0-9]|[1-8][0-9]|9[0-9]|[1-8][0-9]{2}|9[0-8][0-9]|99[0-9]|[1-8][0-9]{3}|9[0-8][0-9]{2}|99[0-8][0-9]|999[0-9]|[1-8][0-9]{4}|9[0-8][0-9]{3}|99[0-8][0-9]{2}|999[0-8][0-9]|9999[0-9]|[1-8][0-9]{5}|9[0-8][0-9]{4}|99[0-8][0-9]{3}|999[0-8][0-9]{2}|9999[0-8][0-9]|99999[0-9]|[1-8][0-9]{6}|9[0-8][0-9]{5}|99[0-8][0-9]{4}|999[0-8][0-9]{3}|9999[0-8][0-9]{2}|99999[0-8][0-9]|999999[0-9]|[1-8][0-9]{7}|9[0-8][0-9]{6}|99[0-8][0-9]{5}|999[0-8][0-9]{4}|9999[0-8][0-9]{3}|99999[0-8][0-9]{2}|999999[0-8][0-9]|9999999[0-9]|[1-8][0-9]{8}|9[0-8][0-9]{7}|99[0-8][0-9]{6}|999[0-8][0-9]{5}|9999[0-8][0-9]{4}|99999[0-8][0-9]{3}|999999[0-8][0-9]{2}|9999999[0-8][0-9]|99999999[0-9]|[1-8][0-9]{9}|9[0-8][0-9]{8}|99[0-8][0-9]{7}|999[0-8][0-9]{6}|9999[0-8][0-9]{5}|99999[0-8][0-9]{4}|999999[0-8][0-9]{3}|9999999[0-8][0-9]{2}|99999999[0-8][0-9]|999999999[0-9]|[1-8][0-9]{10}|9[0-8][0-9]{9}|99[0-8][0-9]{8}|999[0-8][0-9]{7}|9999[0-8][0-9]{6}|99999[0-8][0-9]{5}|999999[0-8][0-9]{4}|9999999[0-8][0-9]{3}|99999999[0-8][0-9]{2}|999999999[0-8][0-9]|9999999999[0-9]|[1-8][0-9]{11}|9[0-8][0-9]{10}|99[0-8][0-9]{9}|999[0-8][0-9]{8}|9999[0-8][0-9]{7}|99999[0-8][0-9]{6}|999999[0-8][0-9]{5}|9999999[0-8][0-9]{4}|99999999[0-8][0-9]{3}|999999999[0-8][0-9]{2}|9999999999[0-8][0-9]|99999999999[0-9]|1000000000000):([!@#$%^&*()][a-z0-9\s])?([!@#$%^&*()][a-z0-9\s])?([!@#$%^&*()][a-z0-9\s])?([!@#$%^&*()][a-z0-9\s])?([!@#$%^&*()][a-z0-9\s])?([!@#$%^&*()][a-z0-9\s])?([!@#$%^&*()][a-z0-9\s])?([!@#$%^&*()][a-z0-9\s])?([!@#$%^&*()][a-z0-9\s])?([!@#$%^&*()][a-z0-9\s])?>'
KEY_REGEX = r'([!@#$%^&*()][a-z\s])'


"""
    Exceptions
"""
class NullEncryptedContent(Exception):
    pass



"""
    Utility Classes
"""

class File():
    def __init__(self, filename, content=None):
        self.content = content
        self.filename = filename

    def save(self):
        with open(str(self.filename), 'w', encoding='utf-8') as file:
            file.write(self.content)
            file.close()
    def read(self):
        with open(str(self.filename), 'r', encoding='utf-8') as file:
            contents = file.read()
            return contents



class Parser():
    def __init__(self, encrypted, schema, lexer: dict = {')': 0,'!': 1,'@': 2,'#': 3,'$': 4,'%': 5,'^': 6,'&': 7,'*': 8,'(': 9}):
        self.encrypted = encrypted
        self.schema = schema
        self.lexer = lexer
        self.combined = str(self.encrypted) + str(self.schema)
        self.dictionary = {}

    def decrypt(self):
        
        # Helper function
        def concat(list):
            result= ''
            for element in list:
                result += str(element)
            return result

        pattern = re.compile(DECRYPTION_REGEX)
        key_pattern = re.compile(KEY_REGEX)

        blocks = re.findall(pattern, self.combined)

        for block in blocks:
            # Code for removing empty items
            block = [chunk for chunk in block if chunk != '']
            signature = block[0]
            chunks = block[1:]
            for chunk in chunks:
                character = re.findall(key_pattern, chunk)
                for i in character:
                    i = list(i)
                    self.dictionary[int(self.lexer[str(i[0])]) + int(signature)] = i[1]
        
        ordered_dictionary = OrderedDict(sorted(self.dictionary.items()))
        final_string = ""
        for i in ordered_dictionary:
            final_string += ordered_dictionary[i]
        return final_string


class Lexer():
    def __init__(self, blocks: list, lexer: dict = {0: ')', 1: '!', 2: '@', 3: '#', 4: '$', 5: '%', 6: '^', 7: '&', 8: '*', 9: '('}):
        self.blocks = blocks
        self.lexer = lexer
    
    
    
    """
        Encrypted:

    """

    def create_encrypted(self):
        blocks = []
        for block in self.blocks:
            final_block = {}
            final_block["signature"] = block["signature"]

            sorted_block = sorted(block["encrypted"])
            for index, item in enumerate(sorted_block):
                sorted_block[index] = int(item)
            
            lexered_block = []
            
            for index in sorted_block:
                lexered_block.append(str(self.lexer.get(index)) + str( block["encrypted"].get(str(index))))

            def concat(list):
                result= ''
                for element in list:
                    result += str(element)
                return result

            final_block["string"] = concat(random.sample(lexered_block, len(lexered_block)))
            

            #blocks.append(new_block)
            blocks.append(final_block)

        self.encrypted_data = blocks    
    
    """
        Schema:
        
    """
    def create_schema(self):
        blocks = []
        for block in self.blocks:
            final_block = {}
            final_block["signature"] = block["signature"]

            sorted_block = sorted(block["schema"])
            for index, item in enumerate(sorted_block):
                sorted_block[index] = int(item)
            
            lexered_block = []
            
            for index in sorted_block:
                lexered_block.append(str(self.lexer.get(index)) + str( block["schema"].get(str(index))))

            def concat(list):
                result= ''
                for element in list:
                    result += str(element)
                return result
            
            final_block["string"] = concat(random.sample(lexered_block, len(lexered_block)))
            

            #blocks.append(new_block)
            blocks.append(final_block)

        self.schema_data = blocks
    
    """
        Generate Files
    """
    
    def generate_files(self): 
        def base_str():
            return (string.ascii_letters+string.digits)   
        def key_gen():
            keylist = [random.choice(base_str()) for i in range(10)]
            return ("".join(keylist))


        encrypted_final = ""
        schema_final = ""
        for block in self.encrypted_data:
            encrypted_string = ("<" + str(block["signature"]) + ":" + str(block["string"]) + ">")
            encrypted_final += encrypted_string
        for block in self.schema_data:
            schema_string = ("<" + str(block["signature"]) + ":" + str(block["string"]) + ">")
            schema_final += schema_string
        
        file_name = str(key_gen())
        encrypted_file = File("encrypted_" + file_name + ".halo", encrypted_final)
        encrypted_file.save()
        
        schema_file = File("schema_" + file_name + ".halo", schema_final)
        schema_file.save()
        return "Files generated successfully at " + str(file_name)
            

"""
    Encrypt/Decrypt Functions
"""

def encrypt(message):

    """
        Removing Punctuation to avoid bug

    """
    def remove_punctuation(my_str):
        punctuations = '''!()-[]{};:'"\,<>./?@#$%^&*_~'''
        no_punct = ""
        for char in my_str:
            if char not in punctuations:
                no_punct = no_punct + char
        return no_punct
    """
    Converting the text into a List() of chunks with the chunk_size = 10
    """
    message = remove_punctuation(message)

    # Lowercasing the message content
    # Unicoding the string incase u r like me and didn't care to set an alias and used python2 all the time
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
        
        
        """
        A recursive function for randomizing the best possible candidates
        """




        def randomize(chunk):
         # Encrypted and Schema Blocks
            chunk_final_indices = []
        
            chunk_random_indices = random.sample(range(0, len(chunk)), random.randint(0, len(chunk)))
        
            #if not chunk_random_indices:
             #   chunk_random_indices.append(0)

            if len(chunk_random_indices) != len(chunk):
                chunk_final_indices = chunk_random_indices
            
            chunk_encrypted = {}
            chunk_schema = {}


            for indice in chunk_dict:
                if int(indice) in chunk_final_indices:
                    chunk_encrypted[str(indice)] = chunk_dict.get(indice)
                else:
                    chunk_schema[str(indice)] = chunk_dict.get(indice)

            #if not chunk_schema:
                #return randomize(chunk)

            #if not chunk_encrypted:
                #return randomize(chunk)
            
            chunk_encrypted = dict(sorted(chunk_encrypted.items(), key=operator.itemgetter(1), reverse=True))
            chunk_schema = dict(sorted(chunk_schema.items(), key=operator.itemgetter(1), reverse=True))
            return chunk_encrypted, chunk_schema
        
        chunk_encrypted, chunk_schema = randomize(chunk)
        
       
        # Appending the encrypted and schema items to the block dictionary
        block["encrypted"] = chunk_encrypted
        block["schema"] = chunk_schema
       

        # Appending the block to the list of blocks
        blocks.append(block)


        # Incrementing the signature count
        signature_count += signature_increment


        
    return blocks
