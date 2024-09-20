import pefile
import requests
import json
def chat(content,model):
    if isinstance(content,str):
        content = [{"role":"user","content":content}]
    url = 'http://127.0.0.1:8000/api/chat'
    headers = {'Content-Type':"application/json"}
    data = {
        'model':model,
        'stream':False,
        'messages':content,
    }
    res = requests.post(url,json=data,headers=headers,timeout=1000).json()
    return res['message']['content']

####################################################
####################################################
####################################################
pe = pefile.PE("d.exe")

# 存储提取的API调用信息
api_calls = []
num = 1

# 遍历每个导入的库
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll_name = entry.dll.decode()

    # 遍历库中的每个导入的API
    for imp in entry.imports:
        if imp.name is None:
            continue
        api_name = imp.name.decode()
        api_calls.append({
            "dll": dll_name,
            "api": api_name
        })
    num += 1

explanation_request = json.dumps(api_calls, indent=4)
explanation_request += "\n请逐个解释这些API的功能，并分析这些API调用是否存在潜在的恶意行为，特别是关注以下行为：\n"
explanation_request += "1. 文件写入和修改行为。\n"
explanation_request += "2. 网络通信相关的API调用。\n"
explanation_request += "3. 系统配置或注册表的修改。\n"
explanation_request += "4. API调用的顺序和组合是否异常。"

api_explanations = chat(explanation_request, 'qwen2.5:14b')
contextual_analysis_prompt = (
        api_explanations + "\n根据以上API调用的解释，请结合以下几点进行判断：\n"
                           "1. 是否有文件或系统配置的修改行为？\n"
                           "2. 是否存在可疑的网络活动？\n"
                           "3. API调用顺序是否符合已知恶意软件的行为模式？\n"
                           "请**仔细**判断该程序是否可能是恶意软件，并且返回一个结果。如果是恶意软件，请返回True，反之返回False。"
)

result = chat(contextual_analysis_prompt, 'qwen2.5:14b').upper()
ask = [{"role":"assistant","content":result},{"role":"user","content":'所以最终返回的内容是True还是False？如果是True，请**只**返回True，反之**只**返回False'}]

print(result)
result = chat(ask,'qwen2.5:14b').upper()
print('****************')
print(result)