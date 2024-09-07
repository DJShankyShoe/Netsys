"""silly little file for my silly little tests"""
import random
def wow_a_test():
    """hey idiot exclude docstring from the linter >:("""
    random.seed()
    if random.randint(0,1)==1:
        print("hello worl")
    else:
        print (">:3c")
wow_a_test()
input("accept your fate?")
