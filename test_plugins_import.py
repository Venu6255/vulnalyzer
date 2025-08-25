import sys
print("sys.path:", sys.path)

try:
    import plugins
    print("plugins module imported successfully")
except ModuleNotFoundError:
    print("plugins module NOT found")
