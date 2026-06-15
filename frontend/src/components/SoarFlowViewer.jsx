import React, { useState, useEffect, useCallback } from 'react';
import ReactFlow, { Background, Controls, MiniMap } from 'reactflow';
import 'reactflow/dist/style.css';

// Fields that describe canvas layout / wiring rather than the task's own
// configuration. They are hidden from the details panel so the analyst sees
// the meaningful nested task data, not rendering noise.
const LAYOUT_FIELDS = new Set([
  'top', 'left', 'properties', 'inputTaskField', 'inputTaskNumber',
]);

function buildTaskSummary(op) {
  // Return an ordered object of the meaningful, human-relevant task fields.
  const summary = {};
  for (const [k, v] of Object.entries(op || {})) {
    if (LAYOUT_FIELDS.has(k)) continue;
    if (v === null || v === undefined || v === '') continue;
    summary[k] = v;
  }
  return summary;
}

export default function SoarFlowViewer({ workflow_json, playbook_constructor, playbook_details, steps }) {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null); // { raw, title }

  const handleNodeMouseEnter = useCallback((event, node) => {
    if (!node?.data?.raw) return;
    setSelected({ raw: node.data.raw, title: node.data.tooltipTitle });
  }, []);

  useEffect(() => {
    // Reset state
    setError(null);
    setNodes([]);
    setEdges([]);
    setSelected(null);

    // Intelligent Prop Extraction: Fallback to workflow_json if individual props aren't passed
    const p_constructor = playbook_constructor || workflow_json?.playbook_constructor;
    const p_details = playbook_details || workflow_json?.playbook_details;
    const p_steps = steps || workflow_json?.steps;

    // Check if we have playbook constructor or playbook details (complex flow)
    if (p_constructor || p_details) {
      try {
        let constructorData = p_constructor;
        while (typeof constructorData === 'string') {
          constructorData = JSON.parse(constructorData);
        }

        let detailsData = p_details;
        while (typeof detailsData === 'string') {
          detailsData = JSON.parse(detailsData);
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
            const tooltipTitle = op.properties?.title || op.title || key;

            // Merge the matching playbook_details entry (child task wiring,
            // names) into the hover payload so the panel shows everything
            // known about the task, not just the constructor view.
            const detail = detailsData && typeof detailsData === 'object'
              ? detailsData[id]
              : undefined;
            const raw = detail ? { ...op, playbook_details: detail } : op;

            // Format labels with a rich styling suitable for SOC
            newNodes.push({
              id: id,
              position: { x: op.left || 0, y: op.top || 0 },
              data: {
                raw,
                tooltipTitle,
                label: (
                  <div className="px-3 py-2 bg-slate-900 border border-slate-700 rounded shadow-lg text-white min-w-[150px] text-xs text-left cursor-help">
                    <div className="font-bold border-b border-slate-800 pb-1 mb-1 text-blue-300">
                      {tooltipTitle}
                    </div>
                    {op.task_type && (
                      <div className="text-[10px] text-slate-400 capitalize">
                        Type: <span className="text-blue-400 font-medium">{op.task_type}</span>
                      </div>
                    )}
                    {op.taskDetails && Object.keys(op.taskDetails).length > 0 && (
                      <div className="text-[10px] text-slate-500 mt-0.5">hover for details</div>
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
    } else if (p_steps && p_steps.length > 0) {
      // Fallback for simple linear steps list
      try {
        const newNodes = [];
        const newEdges = [];

        p_steps.forEach((step, index) => {
          const id = `step-${step.id || index}`;
          newNodes.push({
            id: id,
            position: { x: 250, y: index * 100 + 40 },
            data: {
              raw: step,
              tooltipTitle: step.action || `Step ${index + 1}`,
              label: (
                <div className="px-3 py-2 bg-slate-900 border border-slate-700 rounded shadow-lg text-white min-w-[150px] text-xs text-left cursor-help">
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
            const prevId = `step-${p_steps[index - 1].id || index - 1}`;
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
  }, [workflow_json, playbook_constructor, playbook_details, steps]);

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
    <div style={{ width: '100%', height: '500px' }} className="relative bg-slate-950/50 border border-slate-800 rounded-lg overflow-hidden mt-3">
      {hasNodes ? (
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          onNodeMouseEnter={handleNodeMouseEnter}
        >
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

      {selected && <TaskDetailsPanel selected={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

// Scrollable details panel anchored inside the flow. Appears when a block is
// hovered and stays put so the analyst can scroll through the full nested JSON;
// updates when another block is hovered and can be dismissed with the close (x).
function TaskDetailsPanel({ selected, onClose }) {
  const taskDetails = selected.raw?.taskDetails;
  const hasTaskDetails = taskDetails && Object.keys(taskDetails).length > 0;

  // Everything meaningful except the parts already shown in the header / above.
  const rest = buildTaskSummary(selected.raw);
  delete rest.taskDetails;
  delete rest.task_type;
  delete rest.taskid;
  delete rest.original_title;
  const hasRest = Object.keys(rest).length > 0;

  return (
    <div className="absolute top-2 right-2 bottom-2 w-[340px] max-w-[70%] z-20 flex flex-col bg-slate-900/95 backdrop-blur border border-blue-500/50 rounded-lg shadow-2xl shadow-black/50">
      <div className="px-3 py-2 bg-slate-800 border-b border-slate-700 rounded-t-lg flex items-start justify-between gap-2 flex-shrink-0">
        <div className="min-w-0">
          <div className="text-sm font-bold text-blue-300 break-words">{selected.title}</div>
          <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1 text-[10px] text-slate-400">
            {selected.raw?.task_type && (
              <span>type: <span className="text-blue-400 capitalize">{selected.raw.task_type}</span></span>
            )}
            {selected.raw?.original_title && selected.raw.original_title !== selected.title && (
              <span>action: <span className="text-slate-200">{selected.raw.original_title}</span></span>
            )}
            {selected.raw?.taskid !== undefined && (
              <span>task #: <span className="text-slate-200">{selected.raw.taskid}</span></span>
            )}
          </div>
        </div>
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-white text-sm font-mono leading-none px-1 flex-shrink-0"
          title="Close"
        >
          ✕
        </button>
      </div>

      <div className="p-3 overflow-y-auto flex-1">
        {hasTaskDetails ? (
          <>
            <div className="text-[10px] uppercase tracking-wide text-slate-500 mb-1">Task Details</div>
            <pre className="text-[11px] leading-snug font-mono text-emerald-300 whitespace-pre-wrap break-words">
              {JSON.stringify(taskDetails, null, 2)}
            </pre>
          </>
        ) : (
          <div className="text-[11px] text-slate-500 italic">No task details for this block.</div>
        )}

        {hasRest && (
          <>
            <div className="text-[10px] uppercase tracking-wide text-slate-500 mt-3 mb-1">Other Fields</div>
            <pre className="text-[11px] leading-snug font-mono text-slate-300 whitespace-pre-wrap break-words">
              {JSON.stringify(rest, null, 2)}
            </pre>
          </>
        )}
      </div>
    </div>
  );
}
