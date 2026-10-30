import { useEffect, useState } from "react";

export type StreamState = "connecting" | "live" | "offline";

export function useEventStream(environment: string, onEvent: (event: Record<string, unknown>) => void) {
  const [state, setState] = useState<StreamState>("connecting");

  useEffect(() => {
    let socket: WebSocket | null = null;
    let timer: number | undefined;
    let attempts = 0;
    let closed = false;

    const connect = () => {
      if (closed) return;
      setState("connecting");
      const protocol = window.location.protocol === "https:" ? "wss" : "ws";
      socket = new WebSocket(`${protocol}://${window.location.host}/ws/events?environment=${encodeURIComponent(environment)}`);
      socket.onopen = () => {
        if (closed) return;
        attempts = 0;
        setState("live");
      };
      socket.onmessage = (message) => {
        if (closed) return;
        try {
          const payload = JSON.parse(message.data) as Record<string, unknown>;
          if (payload.type && payload.type !== "heartbeat" && payload.type !== "connected") onEvent(payload);
        } catch {
          // ignore malformed frames
        }
      };
      socket.onclose = (event) => {
        if (closed) return;
        setState("offline");
        if (event.code === 4401 || event.code === 4403) return;
        attempts += 1;
        timer = window.setTimeout(connect, Math.min(15_000, 1_000 * 2 ** attempts));
      };
      socket.onerror = () => {
        // A failed handshake already produces a close event that drives reconnection.
        // Closing a CONNECTING socket here only adds a spurious browser warning.
        if (socket?.readyState === WebSocket.OPEN) socket.close();
      };
    };

    connect();
    return () => {
      closed = true;
      if (timer) window.clearTimeout(timer);
      const target = socket;
      if (!target) return;
      if (target.readyState === WebSocket.CONNECTING) {
        // Closing mid-handshake raises a browser warning; retire it once connected.
        target.addEventListener("open", () => target.close(), { once: true });
      } else if (target.readyState === WebSocket.OPEN) {
        target.close();
      }
    };
  }, [environment, onEvent]);

  return state;
}
