import sys

if __name__ == '__main__':
    filename = sys.argv[1]
    line_content = sys.argv[2:]
    line_content = ' '.join(line_content)
    print(line_content)
    file = open(filename, 'r')
    all_content = file.readlines()
    all_new_content = []
    for text in all_content:
        if text[:-1] != line_content:
            all_new_content.append(text)
    file.close()
    file = open(filename, 'w')
    for text in all_new_content:
        file.write(text.strip() + '\n')
    file.close()
