import json, statistics

with open('/home/lida/SCAEvaluation-main/large_scale/src/element_distribution_old.json') as f:
    content = json.load(f)
    type_dict = content['type_others']
    total_types = sum(type_dict.values())
    type_dict = {k: v for k, v in sorted(type_dict.items(), key=lambda item: item[1])}
    classifier_dict = content['classifier_others']
    total_classifiers = sum(classifier_dict.values())
    classifier_dict = {k: v for k, v in sorted(classifier_dict.items(), key=lambda item: item[1])}
    print(type_dict)
    print(classifier_dict)
    print(total_types)
    print(total_classifiers)
