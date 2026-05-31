import sys
import uuid
import configparser
import os
import re
import subprocess

# sys.path.append("<EXTERNAL_REPO>/APISpecGen/utils/")
from tree_sitter_helper import *
ic.configureOutput(includeContext=True)



# cp = configparser.RawConfigParser()
# cp.read('<EXTERNAL_REPO>/APISpecGen/config/config.cfg')

# TODO: add weggli split data
repo_name = 'kernel'

source_dir = os.environ.get("WEGGLI_SOURCE_DIR", "/path/to/source")
# source_dir = cp.get('URL',repo_name)
# weggli_path = '/path/to/weggli'
weggli_path = os.environ.get("WEGGLI_PATH", "/path/to/weggli")

def get_func_name_from_def(code):
    tree = parser.parse(bytes(code, "utf8"))
    funcs = find_node_by_type(tree,"function_declarator")
    if len(funcs) == 0:
        return ''

    return get_node_content(funcs[0].child_by_field_name("declarator"), code)
    
    # file='/tmp/tmp'
def split_weggli_data(data,repo_name='kernel'):
    # source_dir = cp.get('URL',repo_name)
    # data = open(file).read()
    # ic(data)
    pattern = rf"{source_dir}.*\n"
    res = re.split(pattern,data)
    callers_of_main_api = []
    # ic('inside split_weggli_data')
    for i in range(len(res)):
        if len(res[i]) == 0:
            continue
        funcname = get_func_name_from_def(res[i])
        if funcname=='':
            continue
        callers_of_main_api.append(funcname)
    return callers_of_main_api


def split_weggli_data_with_code(data,repo_name='kernel')->dict:
    # source_dir = cp.get('URL',repo_name)
    func_code_dict = {}
    pattern = rf"{source_dir}.*\n"
    res = re.split(pattern,data)
    for func in res:
        if len(func) == 0:
            continue
        funcname = get_func_name_from_def(func)
        if funcname=='':
            continue
        # make dict
        func_code_dict[funcname] = func
    return func_code_dict

        
def run_weggli_query(query,repo_name='kernel'):
    # source_dir = cp.get('URL',repo_name)
    # generate filename randomly:
    file = uuid.uuid4().hex
    cmd = f"{weggli_path} '{query}' {source_dir} -A 500 -B 500 -l > {file}"
    os.system(cmd)
    try:
        data= open(file).read()
        # remove file
        os.system(f'rm {file}')
    except Exception:
        data = ''
    return data
        

def run_weggli_query_return_res(query):
    cmd = f"{weggli_path} '{query}' {source_dir} -l"
    result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    res = result.stdout.read().decode().split('\n')[0]
    return len(res) > 0
