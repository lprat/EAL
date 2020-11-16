from plyara.utils import rebuild_yara_rule
import plyara
import pathlib
import sys
import yara
if __name__ == "__main__":
    rules = list()
    parser = plyara.Plyara()
    if len(sys.argv) != 2:
        sys.exit()
    for file in pathlib.Path(sys.argv[1]).glob('*.yar*'):
        with open(file, 'r') as f:
            try:
                yararules = parser.parse_string(f.read())
                rules += yararules
            except Exception as e:
                print(f'File: {file} error to parse {str(e)}') 
        parser.clear()
    #print(len(rules), rules)

    rebuilt_rules = str()
    name_rule=[]
    count = 0
    countb = 0
    for rule in rules:
        #verify if compile
        if rule['rule_name'] in name_rule:
            continue
        name_rule.append(rule['rule_name'])
        rverif = rebuild_yara_rule(rule)
        try:
            comp = yara.compile(source=rverif, error_on_warning=True)
            rebuilt_rules += rverif
            count += 1
        except Exception as e:
            print(f'Rule error to parse {str(rverif)}')
            countb += 1
    with open('merged.yara', 'w') as f:
        print(rebuilt_rules, file=f)
    print('Write '+str(count)+ " rules and "+str(countb)+" rules removed for warning")
