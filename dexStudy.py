from dexparser import DEXParser

filedir = '/path/to/classes.dex'
filedir = "D:\\git\\frida-dexdump\\frida_dexdump\\com.csair.mbp\\apk\\classes15.dex"
fp = open(filedir, 'rb')
dex = DEXParser(fileobj=fp.read())

strs = dex.get_strings()
# print(len(strs))
# print(strs[0])
for s in strs:
    # 'Lcom/alibaba/wireless/security/jaq/SecurityCipher;'
    if str(s).lower().find('securitycipher') > -1:
        print(s)
        break

methods = dex.get_methods()
fields = dex.get_fieldids()
class_defs = dex.get_classdef_data()

print("[+]有 {} 个方法".format(len(methods)))
for method in methods:
    class_idx = method['class_idx']
    proto_idx = method['proto_idx']
    name_idx = method['name_idx']
    class_name = str(strs[class_idx])
    # proto = dex.get_protoids()[proto_idx]
    # print(proto)
    # short_proto_idx = str(strs[proto['shorty_idx']])
    method_name = str(strs[name_idx])
    # print(f"class name: {class_name}\t proto: {short_proto_idx}\t name: {name}")
    # break   
    if method_name.lower().find('atlasencryptstring') > -1:
        print("target class {} ".format(class_name))
        print("target method {} ".format(method_name))
        break


for field in fields:
    class_idx = field['class_idx']
    type_idx = field['type_idx']
    name_idx = field['name_idx']
    field_name = str(strs[name_idx])
    if field_name.lower().find("key") > -1:
        print("field name " + field_name)
        break

for class_def in class_defs:
    class_idx = class_defs['class_idx']
    superclass_idx = class_defs['superclass_idx']
    interfaces_off = class_defs['interfaces_off']
    annotation_off = class_defs['annotation_off']
    class_data_off = class_defs['class_data_off']

