
import networkx as nx
import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.append(CURRENT_DIR)

import tree_sitter_helper

parser = tree_sitter_helper.tree_sitter_init()

class CFGAnalyzer:
    @staticmethod
    def assignement_node_id_by_label(G, func):
        labels = nx.get_node_attributes(G, "label")
        func = f' = {func}'
        return next(((id, label[:-1].split(',', 1)[1]) 
                    for id, label in labels.items() 
                    if func in label and '<operator>.assignment' in label), 
                   (None, None))

    @staticmethod
    def callsite_node_id_by_label(G, func):
        labels = nx.get_node_attributes(G, "label")
        func = f'({func},'
        return next(((id, label[:-1].split(',', 1)[1]) 
                    for id, label in labels.items() 
                    if func in label), 
                   (None, None))

    @staticmethod
    def node_id_by_label(G, func):
        labels = nx.get_node_attributes(G, "label")
        func = f'({func},'
        for id, label in labels.items():
            if func in label:
                return id
        return None

    @staticmethod
    def get_func_call(slice):
        tree = parser.parse(bytes(slice, "utf8"))
        calls = tree_sitter_helper.find_node_by_type(tree, "call_expression")
        func = [tree_sitter_helper.get_node_content(call.child_by_field_name("function"), slice) 
                for call in calls]
        func = list(filter(tree_sitter_helper.remove_log_func, func))
        return func