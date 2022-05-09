import sys
import os
from androguard.misc import AnalyzeAPK

def analyze_app(apk_path):
    a, _, dx = AnalyzeAPK(apk_path)
    # 获取类列表
    target_cls = ''
    for cls in dx.get_classes():
        if cls.name.lower().find('securitycipher') > -1:
            print("found target " + cls.name)
            target_cls = cls.name
            break

a, _, dx = AnalyzeAPK('classes15.zip')
for cls in dx.get_classes():
    if cls.name.lower().find('securitycipher') > -1:
        print("found target " + cls.name)
        break


for s in dx.get_strings():
    if s.get_value().lower().find('securitycipher') > -1:
        print("found target " + cls.name)
        break
    print(s.get_orig_value())
    break

if __name__ == "__main__":
    app = ""
    if len(sys.argv) > 1:
        app = sys.argv[1]
    print(f"分析apk {app}")
    analyze_app(app)