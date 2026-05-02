import { useState, useMemo } from 'react'
import { DeviceGraph } from './components/graph/DeviceGraph'
import { TopBar, type AppView } from './components/layout/TopBar'
import { LeftPanel } from './components/layout/LeftPanel'
import { RightPanel } from './components/layout/RightPanel'
import { NotificationStack } from './components/overlays/NotificationStack'
import { useParallaxBackground } from './hooks/useParallaxBackground'
import { useThrottledGraphData } from './hooks/useThrottledGraphData'
import { useGraphStats } from './hooks/useGraphStats'
import { useFilters } from './hooks/useFilters'
import { useScanConfig } from './hooks/useScanConfig'
import { useNotifications } from './hooks/useNotifications'
import { useWebSocket } from './hooks/useWebSocket'
import type { GraphNode } from './types/graph'

const WS_OPTIONS = { url: 'ws://localhost:8080/ws' };

export default function App() {
  const [activeView, setActiveView] = useState<AppView>('map');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const graphLayerRef = useParallaxBackground();
  const { graphData, status } = useThrottledGraphData(WS_OPTIONS);
  const { notifications, dismiss, handleWSMessage } = useNotifications();
  useWebSocket({ ...WS_OPTIONS, onMessage: handleWSMessage, saveLastMessage: false });
  const stats = useGraphStats(graphData);
  const {
    filters,
    filteredData,
    availableChannels,
    availableSecurities,
    toggleGroup,
    setRssiMin,
    setSecurity,
    toggleChannel,
    setMacSearch,
    setActivityWindow,
    resetFilters,
  } = useFilters(graphData);

  const {
    interfaces,
    selectedIface,
    hopperChannels,
    persistence,
    applying,
    loading: configLoading,
    error: configError,
    selectIface,
    applyChannels,
    togglePersistence,
  } = useScanConfig();

  const selectedNode = useMemo(
    () => graphData?.nodes.find(n => n.id === selectedNodeId) ?? null,
    [graphData, selectedNodeId],
  );

  function handleNodeClick(node: GraphNode) {
    setSelectedNodeId(prev => prev === node.id ? null : node.id);
  }

  return (
    <div className="app-shell">
      <NotificationStack notifications={notifications} onDismiss={dismiss} />
      <TopBar
        stats={stats}
        status={status}
        activeView={activeView}
        onViewChange={setActiveView}
      />

      <div className="app-body">
        <LeftPanel
          filters={filters}
          availableChannels={availableChannels}
          availableSecurities={availableSecurities}
          onToggleGroup={toggleGroup}
          onSetRssiMin={setRssiMin}
          onSetSecurity={setSecurity}
          onToggleChannel={toggleChannel}
          onSetMacSearch={setMacSearch}
          onSetActivityWindow={setActivityWindow}
          onReset={resetFilters}
          scanConfig={{
            interfaces,
            selectedIface,
            hopperChannels,
            persistence,
            applying,
            loading: configLoading,
            error: configError,
          }}
          onSelectIface={selectIface}
          onApplyChannels={applyChannels}
          onTogglePersistence={togglePersistence}
        />

        <div ref={graphLayerRef} className="graph-layer">
          <DeviceGraph
            graphData={filteredData}
            onNodeClick={handleNodeClick}
          />
        </div>

        <RightPanel
          node={selectedNode}
          onClose={() => setSelectedNodeId(null)}
        />
      </div>
    </div>
  );
}
