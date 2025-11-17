import networkx as nx

def load_graph_from_edges(edges):
    """
    Створює орієнтований граф із списку ребер.
    edges: список кортежів (u, v)
    """
    G = nx.DiGraph()
    G.add_edges_from(edges)
    return G

def validate_graph(G):
    """
    Перевіряє, що граф не порожній і має хоча б одну вершину
    """
    return G.number_of_nodes() > 0
