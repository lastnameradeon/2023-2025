import itertools

# 生成所有可能的密码组合
# passwords = []
# a = []


# with open('passwords.txt', 'w') as f:
#     for length in range(min_length, max_length + 1):
#         for password in itertools.product(chars, repeat=length):
#             passwords_batch.append(''.join(password))
#             if len(passwords_batch) == 1000:
#                 for password in passwords_batch:
#                     f.write(password + '\n')
#                 passwords_batch = []
# if passwords_batch:
#     for password in passwords_batch:
#         f.write(password + '\n')





# for length in range(1, 13):
#   for combination in itertools.product('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', repeat=length):
#                  passwords.append(''.join(combination))

#for length in range(1, 5):
#   for combination in itertools.product(['ptsh','2023','@'], repeat=length):
#                  passwords.append(''.join(combination))

# for length_1 in range(1, 2):
#    for combination in itertools.product(['Ptsh','PTSH'], repeat=length_1):
#                   a.append(''.join(combination))



# a.extend(['2023', '@'])

# for length_2 in range(3, 4):
#    for combination in itertools.product(a, repeat=length_2):
#                   passwords.append(''.join(combination))

passwords=[]
with open('passwords.txt', 'w') as f:
    for length in range(1, 13):
        for combination in itertools.product('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',repeat=length):
            passwords.append(''.join(combination))
            if len(passwords) == 1000:
                for password in passwords:
                    f.write(password + '\n')
                passwords = []


if passwords:
    for password in passwords:
        f.write(password + '\n')