import React, { useState, useEffect } from 'react';
import ReactFlow, { Background, Controls, MiniMap } from 'reactflow';
import 'reactflow/dist/style.css';

export default function SoarFlowViewer({ playbook_constructor, playbook_details, steps }) {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Reset state
    setError(null);
    setNodes([]);
    setEdges([]);

    // Check if we have playbook constructor or playbook details (complex flow)
    if (playbook_constructor || playbook_details) {
      try {
        let constructorData = playbook_constructor;
        if (typeof constructorData === 'string') {
          constructorData = JSON.parse(constructorData);
          if (typeof constructorData === 'string') {
            constructorData = JSON.parse(constructorData);
          }
        }

        let detailsData = playbook_details;
        if (typeof detailsData === 'string') {
          detailsData = JSON.parse(detailsData);
          if (typeof detailsData === 'string') {
            detailsData = JSON.parse(detailsData);
          }
        }

        if (!constructorData) {
          throw new Error('Playbook constructor data is empty');
        }

        const newNodes = [];
        const newEdges = [];

        // Helper to extract numeric suffix ID from operator name (e.g. "Start Playbook_0" -> "0")
        const extractId = (key) => {
          if (!key) return '';
          const parts = key.split('_');
          return parts[parts.length - 1];
        };

        if (constructorData.operators) {
          Object.entries(constructorData.operators).forEach(([key, op]) => {
            const id = extractId(key);
            
            // Format labels with a rich styling suitable for SOC
            newNodes.push({
              id: id,
              position: { x: op.left || 0, y: op.top || 0 },
              data: {
                label: (
                  <div className="px-3 py-2 bg-slate-900 border border-slate-700 rounded shadow-lg text-white min-w-[150px] text-xs text-left">
                    <div className="font-bold border-b border-slate-800 pb-1 mb-1 text-blue-300">
                      {op.properties?.title || op.title || key}
                    </div>
                    {op.task_type && (
                      <div className="text-[10px] text-slate-400 capitalize">
                        Type: <span className="text-blue-400 font-medium">{op.task_type}</span>
                      </div>
                    )}
                  </div>
                ),
              },
              style: { background: 'transparent', border: 'none', padding: 0 },
            });
          });
        }

        if (constructorData.links) {
          Object.entries(constructorData.links).forEach(([key, link]) => {
            const source = extractId(link.fromOperator);
            const target = extractId(link.toOperator);
            
            if (source && target) {
              newEdges.push({
                id: `edge-${key}`,
                source: source,
                target: target,
                animated: true,
                style: { stroke: '#3b82f6', strokeWidth: 2 },
              });
            }
          });
        }

        setNodes(newNodes);
        setEdges(newEdges);
      } catch (err) {
        console.error('SOAR visualizer parse error:', err);
        setError(err.message);
      }
    } else if (steps && steps.length > 0) {
      // Fallback for simple linear steps list
      try {
        const newNodes = [];
        const newEdges = [];

        steps.forEach((step, index) => {
          const id = `step-${step.id || index}`;
          newNodes.push({
            id: id,
            position: { x: 250, y: index * 100 + 40 },
            data: {
              label: (
                <div className="px-3 py-2 bg-slate-900 border border-slate-700 rounded shadow-lg text-white min-w-[150px] text-xs text-left">
                  <div className="font-bold border-b border-slate-800 pb-1 mb-1 text-emerald-400">
                    {step.action || 'Action'}
                  </div>
                  {step.params && (
                    <div className="text-[10px] text-slate-400 truncate max-w-[160px] font-mono">
                      {JSON.stringify(step.params)}
                    </div>
                  )}
                </div>
              ),
            },
            style: { background: 'transparent', border: 'none', padding: 0 },
          });

          if (index > 0) {
            const prevId = `step-${steps[index - 1].id || index - 1}`;
            newEdges.push({
              id: `edge-${index}`,
              source: prevId,
              target: id,
              animated: true,
              style: { stroke: '#10b981', strokeWidth: 2 },
            });
          }
        });

        setNodes(newNodes);
        setEdges(newEdges);
      } catch (err) {
        setError(err.message);
      }
    }
  }, [playbook_constructor, playbook_details, steps]);

  if (error) {
    return (
      <div className="p-4 bg-red-950/20 border border-red-500/50 rounded text-red-400 text-sm mt-3">
        <div className="font-bold mb-1">Failed to visualize SOAR playbook:</div>
        <div className="font-mono text-xs text-red-300">{error}</div>
      </div>
    );
  }

  const hasNodes = nodes.length > 0;

  return (
    <div style={{ width: '100%', height: '450px' }} className="relative bg-slate-950/50 border border-slate-800 rounded-lg overflow-hidden mt-3">
      {hasNodes ? (
        <ReactFlow nodes={nodes} edges={edges} fitView>
          <Background color="#334155" gap={16} />
          <Controls className="text-slate-800" />
          <MiniMap 
            nodeColor={() => '#1e293b'} 
            maskColor="rgba(15, 23, 42, 0.6)" 
            className="border border-slate-800 rounded bg-slate-900"
          />
        </ReactFlow>
      ) : (
        <div className="absolute inset-0 flex items-center justify-center text-slate-500 text-sm">
          No workflow visualization available
        </div>
      )}
    </div>
  );
}
