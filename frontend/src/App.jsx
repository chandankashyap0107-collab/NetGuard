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
  const interfaces =
    type === 'switch'
      ? []
      : [
          {
            name: type === 'router' ? 'g0/0' : 'eth0',
            ip: '',
            mask: '',
          },
        ];

  return {
    id,
    position,
    data: {
      deviceType: type,
      name,
      label: name,
      interfaces,
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
      current.map((node) => {
        if (node.id !== selectedId) return node;

        const data = { ...node.data };

        if (field === 'name') {
          data.name = value;
          data.label = value;
        } else if (field === 'gateway') {
          data.gateway = value;
        } else {
          const key = field === 'interfaceName' ? 'name' : field;
          data.interfaces = [{ ...data.interfaces[0], [key]: value }];
        }

        return { ...node, data };
      }),
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

              <label>
                Name
                <input
                  value={selectedNode.data.name}
                  onChange={(event) => updateSelected('name', event.target.value)}
                />
              </label>

              {selectedNode.data.deviceType !== 'switch' && (
                <>
                  <label>
                    Interface
                    <input
                      value={selectedNode.data.interfaces[0].name}
                      onChange={(event) =>
                        updateSelected('interfaceName', event.target.value)
                      }
                    />
                  </label>

                  <label>
                    IP address
                    <input
                      value={selectedNode.data.interfaces[0].ip}
                      onChange={(event) => updateSelected('ip', event.target.value)}
                    />
                  </label>

                  <label>
                    Subnet mask
                    <input
                      value={selectedNode.data.interfaces[0].mask}
                      onChange={(event) =>
                        updateSelected('mask', event.target.value)
                      }
                    />
                  </label>
                </>
              )}

              {selectedNode.data.deviceType === 'host' && (
                <label>
                  Gateway
                  <input
                    value={selectedNode.data.gateway}
                    onChange={(event) =>
                      updateSelected('gateway', event.target.value)
                    }
                  />
                </label>
              )}
            </>
          ) : (
            <p>Select a device on the canvas to edit it.</p>
          )}
        </aside>
      </div>
    </main>
  );
}