"""
    Halocipher: Copyright 2020 (Utkarsh Dubey, Dhruv Bhatia)
    Halocipher was built for Halocrypt 2020, you can always use this commercially if you want to get hacked.
"""

# Imports
from functools import partial
from io import StringIO
import random, json, operator, string


"""
    Exceptions
"""
class NullEncryptedContent(Exception):
    pass



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

            final_block["string"] = concat(lexered_block)
            

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

            final_block["string"] = concat(lexered_block)
            

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
        encrypted_file = File(encrypted_final, "encrypted_" + file_name, "halo")
        encrypted_file.save()
        
        schema_file = File(schema_final, "schema_" + file_name, "halo")
        schema_file.save()
        return "Files generated successfully at {}".join(file_name)
            

"""
    Encrypt/Decrypt Functions
"""

def encrypt(message):

    """
    Converting the text into a List() of chunks with the chunk_size = 10
    """


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

            if not chunk_schema:
                return randomize(chunk)

            if not chunk_encrypted:
                return randomize(chunk)
            
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

#print(json.dumps(encrypt("Twenty One Pilots is great"), indent=4))
string_l = encrypt("Twenty One Pilots is great")
new_l = Lexer(string_l)
new_l.create_encrypted()
new_l.create_schema()
new_l.generate_files()
#print(json.dumps(string_l, indent=4))
#print(json.dumps(new_l.create_encrypted(), indent=4))
