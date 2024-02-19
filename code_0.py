import os
import time

# Create 'abc' files
for i in range(1, 50):
    filename = f'abc{i}.txt'
    with open(filename, 'w') as file:
        file.write(f'This is file {i}')
        time.sleep(2)
print("Files created successfully.")