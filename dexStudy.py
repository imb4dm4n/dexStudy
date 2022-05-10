from dexparser import DEXParser, APKParser, disassembler

filedir = '/path/to/classes.dex'
filedir = "D:\\git\\frida-dexdump\\frida_dexdump\\com.csair.mbp\\apk\\4.0.8apk.zip"
filedir = "D:\\git\\frida-dexdump\\frida_dexdump\\com.csair.mbp\\apk\\4.0.8apk.zip"
#E:\git\frida-weapon\FRIDA-DEXDump\frida_dexdump\com.csair.mbp\apk\classes15.dex
# filedir = "e:\\git\\frida-weapon\\frida-dexdump\\frida_dexdump\\com.csair.mbp\\apk\\v4.0.8.zip"

def dump_method(apk_path, target_method=""):
    '''
    dump apk 特定的方法信息
    '''
    fp = open(filedir, 'rb')
    apk = APKParser(fileobj=fp.read())
    dex_names = apk.get_all_dex_filenames()
    # 获取apk包含的 dex 文件名列表
    for dex_name in dex_names:
        if dex_name.find("classes15") == -1:
            continue
        # 根据文件名获取 dex 对象
        dex:DEXParser = apk.get_dex(dex_name)
        # 获取 strings 列表
        strs = dex.get_strings()
        # print(len(strs))
        # print(strs[0])
        for s in strs:
            # 'Lcom/alibaba/wireless/security/jaq/SecurityCipher;'
            if str(s).lower().find('securitycipher') > -1:
                print(s)
                break

        # 获取方法列表
        methods = dex.get_methods()
        # 获取字段列表
        fields = dex.get_fieldids()
        # 获取 class_def 列表, 进一步获取 class_data
        class_defs = dex.get_classdef_data()
        # 获取类型列表, 每一项值都是 字符串表的索引, 得到类名
        types = dex.get_typeids()

        # print("[+]{} 有 {} 个方法".format(dex_name, len(methods)))
        for class_def in class_defs:
            # 得到类型列表索引
            type_id = types[class_def['class_idx']]
            # 得到类名
            class_name = str(strs[type_id])
            # 父类
            superclass_idx = class_def['superclass_idx']
            class_name = str(strs[type_id])
            # 过滤目标类名
            if class_name.lower().find('securitycipher') == -1:
                continue
            # 接口
            interfaces_off = class_def['interfaces_off']
            # class data 偏移
            class_data_off = class_def['class_data_off']
            # class data 数据
            if (class_data_off > 0):
                class_data = dex.get_class_data(class_data_off)
                direct_methods = class_data['direct_methods']
                virtual_methods = class_data['virtual_methods']
                print("has {} direct methods\nhas {} virtual methods".format(len(direct_methods), len(virtual_methods)))
                for method in direct_methods:
                    method_idx = method['diff'] # 方法的索引
                    access_flags = method['access_flags'] # 访问属性和是否构造函数
                    code_off = method['code_off'] # code_off 去拿code_item
                    method = methods[method_idx]
                    class_idx = method['class_idx']
                    proto_idx = method['proto_idx']
                    name_idx = method['name_idx']

                    print("direct method name " + str(strs[name_idx]))
                    print("code offset = {}".format(code_off))
                
                for method in virtual_methods:
                    method_idx = method['diff']
                    access_flags = method['access_flags']
                    code_off = method['code_off']
                    method = methods[method_idx]
                    class_idx = method['class_idx']
                    proto_idx = method['proto_idx']
                    name_idx = method['name_idx']

                    print("virtual method name " + str(strs[name_idx]))
                    print("code offset = {}".format(code_off))
                

            if class_name.lower().find("securitycipher") > -1:
                print("[!]found target class name: " + class_name)
                break

        # for method in methods:
        #     class_idx = method['class_idx']
        #     proto_idx = method['proto_idx']
        #     name_idx = method['name_idx']
        #     # class_name = str(strs[class_idx])
        #     # proto = dex.get_protoids()[proto_idx]
        #     # print(proto)
        #     # short_proto_idx = str(strs[proto['shorty_idx']])
        #     method_name = str(strs[name_idx])
        #     # print(f"class name: {class_name}\t proto: {short_proto_idx}\t name: {name}")
        #     # break   
        #     if method_name.lower().find('atlasencryptstring') > -1:
        #         # print("target class {} ".format(class_name))
        #         # 输出方法对应的类信息
        #         # class_def = class_defs[class_idx]
        #         for class_def in class_defs:
        #             if class_def['class_idx'] == 332 or \
        #                  class_def['class_idx'] == 5116 :
        #                 # found target class
        #                 print("dex is " + dex_name)
        #                 print("target class idx = {} ".format(class_idx))
        #                 print("target method {} ".format(method_name))
        #                 print("target class name {}".format(
        #                     str(strs[types[class_def['class_idx']]])))
        #                 class_data = dex.get_class_data(class_def['class_data_off'])
        #                 static_fields = class_data['static_fields']
        #                 instance_fields = class_data['instance_fields']
        #                 direct_methods = class_data['direct_methods']
        #                 virtual_methods = class_data['virtual_methods']
        #                 for dm in direct_methods:
        #                     diff = dm['diff']
        #                     access_flags = dm['access_flags']
        #                     code_off = dm['code_off']
        #                     print("method code_off @ {}".format(code_off))
        #                 break


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
