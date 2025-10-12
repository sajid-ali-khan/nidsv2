import { useState, useEffect, useRef } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Activity, CheckCircle2, AlertTriangle } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts";
import { toast } from "sonner";

// --- Configuration: Point this to your FastAPI backend ---
// IMPORTANT: If your backend is on another machine (like a VM),
// replace "127.0.0.1" with the actual network IP of that machine.
const BACKEND_URL = "127.0.0.1:8000";
const API_BASE_URL = `http://${BACKEND_URL}/api`;
const WEBSOCKET_URL = `ws://${BACKEND_URL}/ws/events/stream`;

// --- Type Definitions to match the Backend Data Contract ---
type EventPrediction = "Normal Traffic" | "DDoS" | "Port Scanning" | "Brute Force" | "Bots" | "Web Attacks";

interface NetworkEvent {
  flow_id: string;
  timestamp_utc: string;
  source_ip: string;
  dest_ip: string;
  dest_port: number;
  protocol: string;
  prediction: EventPrediction;
}

const ATTACK_TYPES: EventPrediction[] = ["DDoS", "Port Scanning", "Brute Force", "Bots", "Web Attacks"];
const MAX_EVENTS = 100; // Keep the log from growing indefinitely

const Index = () => {
  // --- State Management for Live Data ---
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const ws = useRef<WebSocket | null>(null);

  // --- 1. Initial Data Load (runs once on component mount) ---
  useEffect(() => {
    const fetchInitialEvents = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/events?limit=50`);
        if (!response.ok) {
          toast.error("Failed to fetch initial event data from the server.");
          return;
        }
        const initialEventsData: NetworkEvent[] = await response.json();
        // Reverse to show oldest first, so new live events appear on top
        setEvents(initialEventsData.reverse());
      } catch (error) {
        console.error("Error connecting to the backend API:", error);
        toast.error("Could not connect to the NIDS backend.");
      }
    };
    fetchInitialEvents();
  }, []); // Empty dependency array [] ensures this runs only once.

  // --- 2. Real-Time WebSocket Connection (with reconnection logic) ---
  useEffect(() => {
    const connect = () => {
      ws.current = new WebSocket(WEBSOCKET_URL);

      ws.current.onopen = () => {
        console.log("WebSocket connection established.");
        setIsConnected(true);
        toast.success("Connected to real-time event stream.");
      };

      ws.current.onmessage = (event) => {
        const newEvent: NetworkEvent = JSON.parse(event.data);
        
        // FIX: Prevent duplicate keys by checking if the event already exists
        setEvents((prevEvents) => {
          if (prevEvents.some(e => e.flow_id === newEvent.flow_id)) {
            return prevEvents; // If event exists, don't update state
          }
          // Add the new event to the top and cap the total length
          return [newEvent, ...prevEvents].slice(0, MAX_EVENTS);
        });

        // Trigger a toast notification for detected attacks
        if (newEvent.prediction !== "Normal Traffic") {
          toast.error(`🚨 ${newEvent.prediction} Detected!`, {
            description: `Source: ${newEvent.source_ip} → ${newEvent.dest_ip}:${newEvent.dest_port}`,
          });
        }
      };

      ws.current.onclose = () => {
        console.log("WebSocket connection closed.");
        setIsConnected(false);
        toast.warning("Disconnected. Trying to reconnect in 5 seconds...");
        // Attempt to reconnect after a delay
        setTimeout(() => {
          connect();
        }, 5000);
      };

      ws.current.onerror = (error) => {
        console.error("WebSocket error:", error);
        ws.current?.close(); // This will trigger the onclose handler for reconnection
      };
    };

    connect(); // Initial connection attempt

    // Cleanup function: close the connection when the component is unmounted
    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, []); // Empty dependency array [] ensures this also runs only once.

  // --- All calculations below are now driven by the live state ---
  const totalEvents = events.length;
  const attacksDetected = events.filter((e) => e.prediction !== "Normal Traffic").length;
  const normalTraffic = totalEvents - attacksDetected;

  const attackDistribution = ATTACK_TYPES.map((type) => ({
    name: type,
    value: events.filter((e) => e.prediction === type).length,
  })).filter((item) => item.value > 0);

  const COLORS = [
    "hsl(var(--chart-5))", "hsl(var(--chart-2))", "hsl(var(--chart-4))",
    "hsl(var(--chart-1))", "hsl(var(--destructive))",
  ];

  return (
    <div className="min-h-screen bg-background p-6">
      {/* Header */}
      <header className="mb-8">
        <h1 className="text-4xl font-bold tracking-tight text-foreground flex items-center gap-3">
          <Shield className="h-10 w-10 text-primary" />
          NIDS Real-Time Dashboard
        </h1>
        <p className={`mt-2 text-lg font-semibold ${isConnected ? 'text-success' : 'text-destructive'}`}>
          Live Connection Status: {isConnected ? 'Connected' : 'Disconnected'}
        </p>
      </header>

      {/* Top Stat Cards (Now uses live data) */}
      <div className="mb-8 grid gap-6 md:grid-cols-3">
        <Card className="bg-card border-border">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-card-foreground">Total Events Analyzed</CardTitle>
            <Activity className="h-5 w-5 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-foreground">{totalEvents}</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-card-foreground">Attacks Detected</CardTitle>
            <AlertTriangle className="h-5 w-5 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-destructive">{attacksDetected}</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-card-foreground">Normal Traffic</CardTitle>
            <CheckCircle2 className="h-5 w-5 text-success" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-success">{normalTraffic}</div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Area (Now uses live data) */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Live Event Log */}
        <Card className="bg-card border-border lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-xl font-semibold text-card-foreground flex items-center gap-2">
              <Activity className="h-5 w-5 text-primary animate-pulse-glow" />
              Live Event Log
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-hidden rounded-lg border border-border">
              <div className="grid grid-cols-5 gap-4 bg-secondary px-4 py-3 text-sm font-semibold text-secondary-foreground">
                <div>Time</div>
                <div>Source IP</div>
                <div>Destination IP:Port</div>
                <div>Protocol</div>
                <div>Prediction</div>
              </div>
              <div className="max-h-[600px] overflow-y-auto">
                {events.map((event) => {
                  const isAttack = event.prediction !== "Normal Traffic";
                  return (
                    <div
                      key={event.flow_id}
                      className={`grid grid-cols-5 gap-4 border-b border-border px-4 py-3 text-sm animate-fade-in ${isAttack
                          ? "bg-destructive/10 hover:bg-destructive/20"
                          : "bg-card hover:bg-muted/50"
                        }`}
                    >
                      <div className="text-muted-foreground">{new Date(event.timestamp_utc).toLocaleTimeString()}</div>
                      <div className="font-mono text-foreground">{event.source_ip}</div>
                      <div className="font-mono text-foreground">
                        {event.dest_ip}:{event.dest_port}
                      </div>
                      <div className="font-mono text-foreground">{event.protocol}</div>
                      <div className={`font-semibold ${isAttack ? "text-destructive" : "text-success"}`}>
                        {event.prediction}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Attack Distribution Chart */}
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-xl font-semibold text-card-foreground">Attack Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {attackDistribution.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={attackDistribution}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    fill="#8884d8"
                    paddingAngle={5}
                    dataKey="value"
                    nameKey="name"
                  >
                    {attackDistribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "6px",
                      color: "hsl(var(--card-foreground))",
                    }}
                  />
                  <Legend
                    wrapperStyle={{
                      fontSize: "12px",
                      color: "hsl(var(--muted-foreground))",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[300px] items-center justify-center text-muted-foreground">
                No attack data yet
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Index;

