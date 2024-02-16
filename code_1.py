import os
# Delete all files with names starting with 'abc'
for i in range(1, 50):
    filename = f'abc{i}.txt'
    if os.path.exists(filename):
        os.remove(filename)
print("Files deleted successfully.")
