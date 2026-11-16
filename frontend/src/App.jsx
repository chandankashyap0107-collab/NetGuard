import { useCallback, useState } from 'react';
import {
  addEdge,
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  useEdgesState,
  useNodesState,
} from '@xyflow/react';

import '@xyflow/react/dist/style.css';
import './App.css';

function makeDevice(id, name, type, position) {
  return {
    id,
    position,
    data: {
      deviceType: type,
      name,
      label: name,
      ip: '',
      mask: '',
      gateway: '',
    },
  };
}

const startingNodes = [
  makeDevice('r1', 'Router R1', 'router', { x: 100, y: 120 }),
  makeDevice('sw1', 'Switch SW1', 'switch', { x: 380, y: 120 }),
  makeDevice('h1', 'Host PC1', 'host', { x: 660, y: 120 }),
];

const startingEdges = [
  { id: 'l1', source: 'r1', target: 'sw1' },
  { id: 'l2', source: 'sw1', target: 'h1' },
];

export default function App() {
  const [nodes, setNodes, onNodesChange] = useNodesState(startingNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(startingEdges);
  const [selectedId, setSelectedId] = useState(null);

  const onConnect = useCallback(
    (connection) => setEdges((current) => addEdge(connection, current)),
    [setEdges],
  );

  function addDevice(type) {
    const titles = { router: 'Router', switch: 'Switch', host: 'Host' };
    const title = titles[type];
    const number =
      nodes.filter((node) => node.data.deviceType === type).length + 1;
    const id = `${type}-${crypto.randomUUID()}`;

    setNodes((current) => [
      ...current,
      makeDevice(id, `${title} ${number}`, type, {
        x: 120 + current.length * 60,
        y: 280 + current.length * 35,
      }),
    ]);
    setSelectedId(id);
  }

  function updateSelected(field, value) {
    setNodes((current) =>
      current.map((node) =>
        node.id !== selectedId
          ? node
          : {
              ...node,
              data: {
                ...node.data,
                [field]: value,
                ...(field === 'name' ? { label: value } : {}),
              },
            },
      ),
    );
  }

  const selectedNode = nodes.find((node) => node.id === selectedId);

  return (
    <main className="app-shell">
      <header className="topbar">
        <h1>NetGuard</h1>
        <p>Network topology builder</p>
      </header>

      <div className="workspace">
        <aside className="palette">
          <h2>Devices</h2>
          <button onClick={() => addDevice('router')}>+ Router</button>
          <button onClick={() => addDevice('switch')}>+ Switch</button>
          <button onClick={() => addDevice('host')}>+ Host</button>
        </aside>

        <section className="canvas">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={(_, node) => setSelectedId(node.id)}
            onPaneClick={() => setSelectedId(null)}
            fitView
          >
            <MiniMap />
            <Controls />
            <Background />
          </ReactFlow>
        </section>

        <aside className="properties">
          <h2>Properties</h2>
          {selectedNode ? (
            <>
              <p>{selectedNode.data.deviceType}</p>
              {[
                ['name', 'Name'],
                ['ip', 'IP address'],
                ['mask', 'Subnet mask'],
                ['gateway', 'Gateway'],
              ].map(([field, label]) => (
                <label key={field}>
                  {label}
                  <input
                    value={selectedNode.data[field] ?? ''}
                    onChange={(event) => updateSelected(field, event.target.value)}
                  />
                </label>
              ))}
            </>
          ) : (
            <p>Select a device on the canvas to edit it.</p>
          )}
        </aside>
      </div>
    </main>
  );
}