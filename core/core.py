from collections import defaultdict as dd
from elftools.elf.elffile import ELFFile
from types import FunctionType
from itertools import combinations
from utils.utils import filehash, filetype, elf_translate_arch, pe_translate_arch
from utils.colors import generate_colors, brightness, rgb2hex
from metrics.tlsh import TLSH
from metrics.telfhash import Telfhash
from metrics.imphash import Imphash
from metrics.overhash import Overhash
from metrics.ssdeep import SSDeep
from metrics.peinfo import PEImports, PEExports
from metrics.elfinfo import ELFSymbols
from tqdm import tqdm
import networkx as nx
import numpy as np
import pefile
import gzip
import json
import sys
import os


class Malkom:
    METRICS_GENERIC = {
        'ssdeep': SSDeep,
        'overhash': Overhash
    }

    METRICS_PE = {
        'tlsh': TLSH,
        'imphash': Imphash,
        'peimports': PEImports,
        'peexports': PEExports
    }

    METRICS_ELF = {
        'telfhash': Telfhash,
        'elfsymbols': ELFSymbols
    }

    def __init__(self, output_name, dot,
                 allowed_archs=None, name_len=6,
                 edge_metric='tlsh', metric_keys={},
                 outdir='results', threshold=90,
                 metadata={}, clusters=False,
                 verbose=True):
        self.output_name = output_name
        self.nx = nx.Graph()
        self.dot = dot
        self.similarities = []
        self.log = dd(lambda: 0)
        self.stats = {}
        self.verbose = verbose
        self.allowed_archs = allowed_archs
        self.name_len = name_len
        self.edge_metric = edge_metric
        self.metric_keys = {}
        self.metric_keys.update(Malkom.METRICS_GENERIC) 
        self.metric_keys.update(Malkom.METRICS_PE)
        self.metric_keys.update(Malkom.METRICS_ELF)
        self.metric_keys.update(metric_keys)
        self.mkm = dd(dict)
        self.outdir = outdir
        self.threshold = threshold
        self.metadata = metadata
        self.clusters = clusters

    def store_file_metrics(self, path, filehash, metrics):
        for metric_name in metrics:
            MyMetric = metrics[metric_name]

            metric_value = MyMetric(path).value
            if metric_value:
                self.mkm[filehash][metric_name] = metric_value
                self.log[f'{metric_name}_present'] += 1

    def extract_metrics(self, samples_path):
        if self.verbose:
            print('[+] Extracting MKM metrics...')

        dirlist = os.walk(samples_path)

        idx = 0
        samples_list = [os.path.join(filepath, fname) for filepath, _, files in dirlist for fname in files]
        self.log['total'] = len(samples_list)

        for path in tqdm(samples_list):
            idx += 1

            sha = filehash(path)
            ftype = filetype(path)

            self.mkm[sha]['path'] = path
            self.mkm[sha]['ftype'] = ftype

            if self.metadata and sha in self.metadata:
                self.mkm[sha]['metadata'] = self.metadata[sha]

            self.store_file_metrics(path, sha, Malkom.METRICS_GENERIC)

            try:
                if ftype == 'ELF':
                    elf_file = ELFFile(open(path, 'rb'))
                    if self.allowed_archs:
                        allowed_machines = list(map(elf_translate_arch, self.allowed_arch))
                        if elf_file['e_machine'] not in allowed_machines:
                            self.log['ignored_archs'] += 1
                            continue

                    self.store_file_metrics(path, sha, Malkom.METRICS_ELF)
                elif ftype == 'PE':
                    pe_file = pefile.PE(path)
                    if self.allowed_archs:
                        allowed_machines = list(map(pe_translate_arch, self.allowed_arch))
                        if pe_file.FILE_HEADER.Machine not in allowed_machines:
                            self.log['ignored_archs'] += 1
                            continue

                    self.store_file_metrics(path, sha, Malkom.METRICS_PE)
            except Exception:
                self.log['error'] += 1

            sys.stdout.write(
                '\r[+] %d/%d (%.2f%%)' % (idx, self.log['total'], idx * 100 / self.log['total'])
            )

            sys.stdout.write('\n')

    def compute_similarities(self, similarity_fn=None):
        if self.verbose:
            print('[~] Computing similarities.')

        for (b1, b2) in combinations(self.mkm, 2):
            sim_metric = 0

            if similarity_fn and isinstance(similarity_fn, FunctionType):
                sim_metric = similarity_fn(self.mkm[b1], self.mkm[b2])
            else:
                metric_obj = self.metric_keys[self.edge_metric]

                if self.edge_metric in self.mkm[b1] and self.edge_metric in self.mkm[b2]:
                    metric_value_b1 = self.mkm[b1][self.edge_metric]
                    metric_value_b2 = self.mkm[b2][self.edge_metric]
                    try:
                        sim_metric = metric_obj(value=metric_value_b1).similarity(
                            metric_obj(value=metric_value_b2)
                        )
                    except Exception as e:
                        print(e)
                        pass

            if sim_metric != 0:
                self.similarities.append((sim_metric, b1, b2))

    def compute_statistics(self):
        if self.verbose:
            print('[+] Generating graph statistics...')

        try:
            avg_clust = nx.average_clustering(self.nx)
        except Exception:
            avg_clust = None
        maximal_cliques = nx.find_cliques(self.nx)
        nodes_per_component = []

        avg_weights = []
        var_weights = []
        for component in self.components:
            nodes_per_component.append(component.nodes())

            edges = component.edges()
            weights = [component.edges[edge]['weight'] for edge in edges]
            avg_weights.append(sum(weights) / len(edges) if len(edges) != 0 else -1)
            var_weights.append(np.var(weights))

        n_nodes_per_component = list(map(lambda x: len(list(x)), nodes_per_component))
        avg_nodes_per_component = np.mean(n_nodes_per_component)

        self.stats = {
            'n_nodes_per_component': n_nodes_per_component,
            'avg_nodes_per_component': avg_nodes_per_component,
            'avg_weights_per_component': avg_weights,
            'var_weights_per_component': var_weights,
            'avg_clust_coeff': avg_clust,
            'n_isolates': len(list(nx.isolates(self.nx))),
            'n_maximal_cliques': len(list(maximal_cliques)),
        }

        if self.verbose:
            print('[Statistics]')
            print(json.dumps(self.stats, indent=2))

    def mkm_dump(self, path):
        with gzip.open(path, 'wb') as mkmfile:
            mkmfile.write(json.dumps(dict(self.mkm)).encode('utf-8'))

    def mkm_load(self, path):
        with gzip.open(path, 'rb') as mkmfile:
            obj = json.loads(mkmfile.read())
            self.mkm = dd(dict, obj)

    def build_graph(self, isolates=False, colorize_node=None,
                    colorize_edge=None, node_labeller=None):
        if self.verbose:
            print('[~] Building graph...')

        # Label binaries
        self.names = {}
        self.names_inv = {}
        for fhash in self.mkm:
            label = None

            # If there's an explicit labeller, try to use it.
            if node_labeller is not None:
                label = node_labeller(fhash)

            # If it can't establish a label, just use the first 3 bytes of the hash
            if label is None:
                label = fhash[:self.name_len]

            self.names[fhash] = label
            self.names_inv[label] = fhash

        # Create all nodes in NetworkX
        for fhash in self.mkm:
            mkm_obj = self.mkm[fhash]

            w = 0.1
            h = w

            self.log['nodes'] += 1

            if colorize_node is not None:
                fill_color_rgb, text_color_rgb = colorize_node(mkm_obj, fhash)
                fill_color = rgb2hex(fill_color_rgb)
                text_color = rgb2hex(text_color_rgb)
            else:
                fill_color, text_color = ('white', 'black')

            self.nx.add_node(
                self.names[fhash],
                color=fill_color,
                font_color=text_color,
                size=h + 0.5
            )

        # Create similarity edges in NetworkX
        for metric_value, a, b in sorted(self.similarities, reverse=True):
            if metric_value >= self.threshold:
                edge_color = colorize_edge(metric_value) if colorize_edge is not None else 'red'
                self.nx.add_edge(
                    self.names[a],
                    self.names[b],
                    color=edge_color,
                    weight=metric_value
                )

                self.log['edges'] += 1

        # Remove isolates from NetworkX graph if option is not chosen
        self.isolates = list(nx.isolates(self.nx))
        if not isolates:
            for node in self.isolates:
                self.nx.remove_node(node)

        components = nx.connected_components(self.nx)
        self.components = [self.nx.subgraph(comp).copy() for comp in components]

        n_components = len(self.components)
        n_isolates = len(self.isolates)

        print(f'[+] Found {n_components} families & {n_isolates} isolated samples.')

        if not self.clusters:
            for v, data in self.nx.nodes(data=True):
                self.dot.node(
                    v, fillcolor=data['color'], fontcolor=data['font_color'],
                    style='filled', fixedsize='true',
                    width=str(w + 0.5), height=str(h + 0.5), fontsize='6'
                )
        else:
            # Calculate subgraphs that should be built
            clusters = dd(list)
            for v, data in self.nx.nodes(data=True):
                cluster_name = 'main'
                if self.names_inv[v] in self.metadata:
                    if 'cluster' in self.metadata[self.names_inv[v]]:
                        cluster_name = self.metadata[self.names_inv[v]]['cluster']
                clusters[cluster_name].append((v, data))

            # Put nodes in each subgraph
            for cluster_name in clusters:
                with self.dot.subgraph(name=f'cluster_{cluster_name}') as subgraph:
                    subgraph.attr(label=cluster_name)
                    for v, data in clusters[cluster_name]:
                        subgraph.node(
                            v, fillcolor=data['color'], fontcolor=data['font_color'],
                            style='filled', fixedsize='true',
                            width=str(w + 0.5), height=str(h + 0.5), fontsize='6'
                        )

        for v1, v2, data in self.nx.edges(data=True):
            self.dot.edge(
                v1, v2, color=data['color']
            )

    def print_components(self):
        for component_idx in range(len(self.components)):
            component_nodes = self.components[component_idx]
            for node in component_nodes:
                node_hash = self.names_inv[node]
                print(f"Group {component_idx+1}: {node} {self.mkm[node_hash]['path']}")

    def write_results(self, log=True, dot=True, stats=True, colors=True, gexf=False):
        results_dir = self.outdir
        logpath = os.path.join(results_dir, f'{self.output_name}.log.json')
        dotpath = os.path.join(results_dir, f'{self.output_name}.dot')
        gexfpath = os.path.join(results_dir, f'{self.output_name}.gexf')
        statspath = os.path.join(results_dir, f'{self.output_name}.stats.json')
        colorspath = os.path.join(results_dir, f'{self.output_name}.colors.json')

        if log:
            with open(logpath, 'w') as logfile:
                json.dump(self.log, logfile)
            if self.verbose:
                print(f'[+] Log written to {logpath}.')

        if dot:
            with open(dotpath, 'w') as dotfile:
                dotfile.write(self.dot.source)
            if self.verbose:
                print(f'[+] Graphviz dot written to {dotpath}.')

        if stats:
            with open(statspath, 'w') as statsfile:
                json.dump(self.stats, statsfile)
            if self.verbose:
                print(f'[+] Statistics file written to {statspath}.')

        if gexf:
            nx.write_gexf(self.nx, gexfpath)

        colors_obj = {}
        if colors:
            n_components = len(self.components)
            fill_colors = generate_colors(n_components)
            for components_idx in range(n_components):
                for node in self.components[components_idx]:
                    fill_color = fill_colors[components_idx]
                    text_color = (0, 0, 0)
                    if brightness(fill_color) < 65:
                        text_color = (255, 255, 255)

                    colors_obj[self.names_inv[node]] = (fill_color, text_color)

            with open(colorspath, 'w') as colorsfile:
                json.dump(colors_obj, colorsfile)
            if self.verbose:
                print(f'[+] Colors file written to "{colorspath}".')

    def plot_graph(self, engine='sfdp', overlap='false', splines='spline', ext='png'):
        if self.verbose:
            print('[~] Plotting graph...')
        results_dir = self.outdir
        output_name = self.output_name
        path = os.path.join(results_dir, output_name)
        cmd = '/bin/sh -c "dot -x -K%s -Goverlap=%s -Gsplines=%s -T%s %s.dot > %s.%s"' % (engine, overlap, splines, ext, path, path, ext)
        os.system(cmd)
