import { useState, useEffect, useMemo, useCallback, useRef, useLayoutEffect } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

type Node = {
  id: string;
  label: string;
  color: string;
  cves: string[];
  x?: number;
  y?: number;
  val?: number;
};

type Link = {
  source: string | Node;
  target: string | Node;
};

type GraphData = {
  nodes: Node[];
  links: Link[];
};

function useElementSize<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      setSize({ width, height });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  return [ref, size] as const;
}

function App() {
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], links: [] });
  const [focusedNode, setFocusedNode] = useState<Node | null>(null);
  const [retainedNodes, setRetainedNodes] = useState<Set<string>>(new Set());
  const [retainChecked, setRetainChecked] = useState(false);
  const [showLabels, setShowLabels] = useState(true);
  const [containerRef, { width, height }] = useElementSize<HTMLDivElement>();

  useEffect(() => {
    fetch('http://localhost:3000/api/graph')
      .then(res => res.json())
      .then((data: GraphData) => setGraphData(data))
      .catch(err => console.error("Failed to fetch graph:", err));
  }, []);

  const adjacencyList = useMemo(() => {
    const list = new Map<string, string[]>();
    graphData.nodes.forEach(n => list.set(n.id, []));
    graphData.links.forEach(l => {
      const source = typeof l.source === 'object' ? l.source.id : l.source;
      const target = typeof l.target === 'object' ? l.target.id : l.target;
      if (list.has(source)) list.get(source)!.push(target);
      if (list.has(target)) list.get(target)!.push(source);
    });
    return list;
  }, [graphData]);

  const getNeighbors = useCallback((nodeId: string, depth: number) => {
    const visited = new Set<string>([nodeId]);
    let currentLevel = [nodeId];
    for (let i = 0; i < depth; i++) {
      const nextLevel: string[] = [];
      for (const n of currentLevel) {
        const adjs = adjacencyList.get(n) || [];
        for (const adj of adjs) {
          if (!visited.has(adj)) {
            visited.add(adj);
            nextLevel.push(adj);
          }
        }
      }
      currentLevel = nextLevel;
    }
    return visited;
  }, [adjacencyList]);

  const revealedNodeIds = useMemo(() => {
    if (!focusedNode) return new Set<string>();
    return getNeighbors(focusedNode.id, 2);
  }, [focusedNode, getNeighbors]);

  const { visibleNodes, visibleLinks } = useMemo(() => {
    const visibleIds = new Set<string>();

    const nodes = graphData.nodes.filter(n => {
      if (n.color !== 'White') {
        visibleIds.add(n.id);
        return true;
      }
      if (retainedNodes.has(n.id)) {
        visibleIds.add(n.id);
        return true;
      }
      if (revealedNodeIds.has(n.id)) {
        visibleIds.add(n.id);
        return true;
      }
      return false;
    });

    const links = graphData.links.filter(l => {
      const source = typeof l.source === 'object' ? l.source.id : l.source;
      const target = typeof l.target === 'object' ? l.target.id : l.target;
      return visibleIds.has(source) && visibleIds.has(target);
    });

    return { visibleNodes: nodes, visibleLinks: links };
  }, [graphData, retainedNodes, revealedNodeIds]);

  const handleNodeClick = useCallback((node: Node) => {
    setFocusedNode(node);
    // When focusing a new node, see if all its revealed white nodes are already retained
    // If we just reset to false, that's easiest. But to be accurate, we can check.
    // Let's just reset to false.
    setRetainChecked(false);
  }, []);

  const handleRetainToggle = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const checked = e.target.checked;
    setRetainChecked(checked);
    if (checked && focusedNode) {
      const newRetained = new Set(retainedNodes);
      revealedNodeIds.forEach(id => newRetained.add(id));
      setRetainedNodes(newRetained);
    } else if (!checked && focusedNode) {
      const newRetained = new Set(retainedNodes);
      revealedNodeIds.forEach(id => newRetained.delete(id));
      setRetainedNodes(newRetained);
    }
  }, [focusedNode, retainedNodes, revealedNodeIds]);

  const handleClosePanel = () => {
    setFocusedNode(null);
    setRetainChecked(false);
  };

  return (
    <div ref={containerRef} style={{ position: 'relative', width: '100vw', height: '100vh', overflow: 'hidden' }}>
      {width > 0 &&
        <ForceGraph2D
          width={width}
          height={height}
          graphData={{ nodes: visibleNodes, links: visibleLinks }}
          nodeCanvasObject={(node, ctx, globalScale) => {
            // Assume node is of type Node
            const n = node as Node;
            const isRevealedOnly = n.color === 'White' && !retainedNodes.has(n.id) && revealedNodeIds.has(n.id);
            const color = isRevealedOnly ? 'rgba(200,200,200,0.3)' : n.color;

            const size = 5;
            ctx.beginPath();
            ctx.arc(n.x!, n.y!, size, 0, 2 * Math.PI, false);
            ctx.fillStyle = color;
            ctx.fill();
            ctx.strokeStyle = '#333';
            ctx.stroke();

            if (!showLabels) return;

            const label = n.label;
            const fontSize = 12 / globalScale;
            ctx.font = `${fontSize}px Sans-Serif`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'top';
            ctx.fillStyle = isRevealedOnly ? 'rgba(0,0,0,0.5)' : 'rgba(200,200,200, 0.5)';
            ctx.fillText(label, n.x!, n.y! + size + 2);
          }}
          onNodeClick={(node) => handleNodeClick(node as Node)}
          linkDirectionalArrowLength={3.5}
          backgroundColor='rgb(18,18,18)'
          linkColor={() => 'rgba(255,255,255,0.05)'}
          linkDirectionalArrowColor={() => 'rgba(255,255,255,0.6)'}
          dagMode='td'
        />}

      <div
        style={{ position: 'absolute', bottom: 20, left: '50%', zIndex: 10 }}
      >
        <button
          onClick={() => setShowLabels(s => !s)}
        >
          {showLabels ? 'Hide labels' : 'Show labels'}
        </button>
      </div>

      {graphData.nodes.length > 0 && visibleNodes.length === 0 && (
        <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', textAlign: 'center', background: 'rgba(255,255,255,0.9)', padding: '20px', borderRadius: '8px', zIndex: 10 }}>
          <h2>🎉 All {graphData.nodes.length} derivations are safe!</h2>
          <p>No vulnerabilities or transitive risks detected in this closure.</p>
          <button onClick={() => setRetainedNodes(new Set(graphData.nodes.map(n => n.id)))}>
            Show All Nodes Anyway
          </button>
        </div>
      )}

      {focusedNode && (
        <div style={{
          position: 'absolute',
          top: 0,
          right: 0,
          width: '350px',
          height: '100vh',
          backgroundColor: '#fff',
          borderLeft: '1px solid #ccc',
          boxShadow: '-2px 0 5px rgba(0,0,0,0.1)',
          padding: '20px',
          overflow: 'auto',
          boxSizing: 'border-box'
        }}>
          <button onClick={handleClosePanel} style={{ float: 'right' }}>X</button>
          <h2>{focusedNode.label}</h2>

          <div style={{ marginBottom: '20px' }}>
            <label>
              <input type="checkbox" checked={retainChecked} onChange={handleRetainToggle} />
              Retain adjacent node view
            </label>
          </div>

          <p>
            <a href={`https://lazamar.co.uk/nix-versions/?channel=nixpkgs-unstable&package=${focusedNode.label.split('-')[0]}`} target="_blank" rel="noreferrer">
              Search nix-versions
            </a>
          </p>
          <p style={{ fontSize: '0.9em', color: '#666' }}>
            If not found on nix-versions, it is not part of nixpkgs.
          </p>

          <h3>CVEs</h3>
          {focusedNode.cves && focusedNode.cves.length > 0 ? (
            <ul>
              {focusedNode.cves.map(cve => (
                <li key={cve}>{cve}</li>
              ))}
            </ul>
          ) : (
            <p>No CVEs associated.</p>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
