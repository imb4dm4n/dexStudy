from dexparser import DEXParser, APKParser

filedir = '/path/to/classes.dex'
filedir = "D:\\git\\frida-dexdump\\frida_dexdump\\com.csair.mbp\\apk\\classes15.dex"
#E:\git\frida-weapon\FRIDA-DEXDump\frida_dexdump\com.csair.mbp\apk\classes15.dex
filedir = "e:\\git\\frida-weapon\\frida-dexdump\\frida_dexdump\\com.csair.mbp\\apk\\v4.0.8.zip"

def dump_method(apk_path, target_method=""):
    '''
    dump apk 特定的方法信息
    '''
    fp = open(filedir, 'rb')
    apk = APKParser(fileobj=fp.read())
    dex_names = apk.get_all_dex_filenames()
    for dex_name in dex_names:
        dex = apk.get_dex(dex_name)
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

        # print("[+]{} 有 {} 个方法".format(dex_name, len(methods)))
        for method in methods:
            class_idx = method['class_idx']
            proto_idx = method['proto_idx']
            name_idx = method['name_idx']
            # class_name = str(strs[class_idx])
            # proto = dex.get_protoids()[proto_idx]
            # print(proto)
            # short_proto_idx = str(strs[proto['shorty_idx']])
            method_name = str(strs[name_idx])
            # print(f"class name: {class_name}\t proto: {short_proto_idx}\t name: {name}")
            # break   
            if method_name.lower().find('atlasencryptstring') > -1:
                # print("target class {} ".format(class_name))
                # 输出方法对应的类信息
                # class_def = class_defs[class_idx]
                for class_def in class_defs:
                    if class_def['class_idx'] == 332 or \
                         class_def['class_idx'] == 5116 :
                        # found target class
                        print("target class idx = {} ".format(class_idx))
                        print("target method {} ".format(method_name))
                        print("target class name {}".format(str(strs[class_def['class_idx']])))
                        class_data = dex.get_class_data(class_def['class_data_off'])
                        static_fields = class_data['static_fields']
                        instance_fields = class_data['instance_fields']
                        direct_methods = class_data['direct_methods']
                        virtual_methods = class_data['virtual_methods']
                        for dm in direct_methods:
                            diff = dm['diff']
                            access_flags = dm['access_flags']
                            code_off = dm['code_off']
                            print("method code_off @ {}".format(code_off))
                        break


        # for field in fields:
        #     class_idx = field['class_idx']
        #     type_idx = field['type_idx']
        #     name_idx = field['name_idx']
        #     field_name = str(strs[name_idx])
        #     if field_name.lower().find("key") > -1:
        #         print("field name " + field_name)
        #         break

        for class_def in class_defs:
            class_idx = class_def['class_idx']
            if class_idx == 332:
                print("332 class idx = {}".format(class_idx))
            # break
            superclass_idx = class_def['superclass_idx']
            interfaces_off = class_def['interfaces_off']
            annotation_off = class_def['annotation_off']
            class_data_off = class_def['class_data_off']

dump_method(filedir)
