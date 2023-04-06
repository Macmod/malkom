#!/usr/bin/env python
from core.core import Malkom
from graphviz import Graph
from utils.colors import rgb2hex
import argparse
import json
import sys
import os

if __name__ == '__main__':
    BANNER = (
        "   _____           .__    __                     ",
        "  /     \  _____   |  |  |  | __  ____    _____  ",
        " /  \ /  \ \__  \  |  |  |  |/ / /  _ \  /     \ ",
        "/    Y    \ / __ \_|  |__|    < (  <_> )|  Y Y  \\",
        "\____|__  /(____  /|____/|__|_ \ \____/ |__|_|  /",
        "        \/      \/            \/              \/ "
    )

    print('\n'.join(BANNER))

    EDGE_METRICS = list(Malkom.METRICS_ELF.keys())
    EDGE_METRICS += list(Malkom.METRICS_PE.keys()) 
    EDGE_METRICS += list(Malkom.METRICS_GENERIC.keys())

    parser = argparse.ArgumentParser(
        description='',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('outname', help='Name for result files')
    parser.add_argument('--indir', help='A directory with malware samples')
    parser.add_argument('--outdir', help='Output directory.', default='results')
    parser.add_argument('--mkmdir', help='Directory to store MKM files.', default='cache')
    parser.add_argument('--metric', help='Metric to use for graph edges.',
                        choices=EDGE_METRICS,
                        default='tlsh')
    parser.add_argument('--threshold', type=float,
                        help='Similarity threshold to use for graph edges (%%).', default=80)
    parser.add_argument('--plot', action='store_true',
                        help='Plot graph from Graphviz dot file.')
    parser.add_argument('--colors', default='colors.json',
                        help='Colorize nodes based in the provided JSON file mapping SHA256s to RGB colors.')
    parser.add_argument('--write-colors', action='store_true',
                        help='Write color mappings in results directory based in the components found.')
    parser.add_argument('--mkm', help='MKM file to use as input instead of extracting metrics from a directory of samples.')
    parser.add_argument('--write-mkm', action='store_true',
                        help='Save metrics information in MKM file.')
    parser.add_argument('--clusters', action='store_true',
                        help='Cluster nodes by the "cluster" key from their metadata into Graphviz subgraphs.')
    parser.add_argument('--metadata', default='metadata.json',
                        help='JSON mapping SHA256s to metadata dictionary to import into the MKM.')
    parser.add_argument('--write-gexf', action='store_true',
                        help='Write graph in GEXF (Graph Exchange XML Format) in results directory.')
    parser.add_argument('--stats', action='store_true',
                        help='Compute statistics on the constructed graph.')
    parser.add_argument('--isolates', action='store_true',
                        help='Show isolated nodes (those without similarity to any other nodes).')
    parser.add_argument('--groups', action='store_true',
                        help='Show members of each connected component.')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose mode.')
    parser.add_argument('--layout-engine', default='sfdp',
                        help='Layout engine to use for graph plot.')
    parser.add_argument('--archs', help='Allowed architectures', default=None)
    parser.add_argument('--ext', help='Extension for Graphviz plot', default='png')

    args = parser.parse_args()

    if not args.mkm and not args.indir:
        print('[-] You must specify at least one of --mkm or --indir to run Malkom. Read the --help for detailed instructions.')
        sys.exit(1)

    # Load information into Malkom
    colors = {}
    try:
        with open(args.colors) as f:
            colors = json.load(f)
        if args.verbose:
            print(f'[+] Colors: "{args.colors}"')
    except Exception:
        print(f'[~] Could not open colors file "{args.colors}". Ignoring...')

    def get_node_color(mkm_obj, fhash):
        if fhash in colors:
            return colors[fhash]

        return ((255, 255, 255), (0, 0, 0))

    threshold = args.threshold / 100.0

    def get_edge_color(metric_value):
        ecolor = None

        if metric_value >= threshold:
            ecolor = rgb2hex((round(metric_value * 255), 0, 0))

        return ecolor

    edge_metric = args.metric
    indir = args.indir
    outdir = args.outdir
    outname = args.outname
    archs = args.archs.split(',') if args.archs else None

    clusters = args.clusters

    metadata = {}
    try:
        with open(args.metadata) as metadatafile:
            metadata.update(json.load(metadatafile))

        if args.verbose:
            print(f'[+] Metadata: "{args.metadata}"')
    except Exception:
        print(f'[~] Could not open metadata file "{args.metadata}". Ignoring...')

    def get_metadata_label(fhash):
        if fhash in metadata and 'label' in metadata[fhash]:
            return metadata[fhash]['label']

    # Default Graphviz parameters
    dot = Graph(
        graph_attr=[('outputorder', 'edgesfirst')],
        edge_attr=[
            ('dir', 'both'), ('arrowhead', 'dot'),
            ('arrowtail', 'dot'), ('arrowsize', '0.4')
        ]
    )

    malkom = Malkom(outname, dot,
                    allowed_archs=archs,
                    edge_metric=edge_metric,
                    outdir=outdir,
                    threshold=threshold,
                    metadata=metadata,
                    clusters=clusters,
                    verbose=args.verbose)

    cachepath_mkm = os.path.join(args.mkmdir, f'{args.outname}.mkm')
    if args.mkm is not None:
        malkom.mkm_load(args.mkm)
        print(f'[+] Data loaded from "{args.mkm}".')

    if indir is not None:
        malkom.extract_metrics(indir)
        print(f'[+] Data extracted from samples at "{indir}".')
        if args.write_mkm:
            malkom.mkm_dump(cachepath_mkm)

    malkom.compute_similarities()

    malkom.build_graph(isolates=args.isolates,
                       colorize_node=get_node_color,
                       colorize_edge=get_edge_color,
                       node_labeller=get_metadata_label)

    if args.groups:
        malkom.print_components()

    if args.stats:
        malkom.compute_statistics()

    malkom.write_results(
        stats=args.stats,
        colors=args.write_colors,
        gexf=args.write_gexf
    )

    if args.plot:
        malkom.plot_graph(
            engine=args.layout_engine,
            ext=args.ext
        )

    if args.verbose:
        print('[Graph]', dict(malkom.log))

    output_prefix = os.path.join(args.outdir, args.outname)
    print(f'[+] Output: {output_prefix}.*')
