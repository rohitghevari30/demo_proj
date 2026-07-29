// Root dashboard component — wire in the components below as each
// level's tooling starts producing real output.
import ScanResults from "./components/ScanResults";
import DastResults from "./components/DastResults";
import NetworkStatus from "./components/NetworkStatus";
import IncidentReports from "./components/IncidentReports";
import SystemHealth from "./components/SystemHealth";

export default function App() {
  return (
    <div>
      <h1>SecureApp Pipeline — Dashboard</h1>
      <ScanResults />
      <DastResults />
      <NetworkStatus />
      <IncidentReports />
      <SystemHealth />
    </div>
  );
}
