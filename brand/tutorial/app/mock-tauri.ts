// Stand-in for the four Tauri APIs the desktop UI uses, so the real interface
// can run inside the tutorial video (an iframe) with example data.
//
// Every command goes to the video page (window.parent.svxMock), which decides
// the answer for the current scene. The page can also fire events
// (window.svxEmit) and file drops (window.svxDrop).
type Handler = (event: { payload: unknown }) => void;

interface Host {
  svxMock(cmd: string, args: Record<string, unknown> | undefined, frame: string): Promise<unknown> | unknown;
}

const frame = new URLSearchParams(location.search).get("frame") ?? "main";
const host = window.parent as unknown as Host;
const listeners = new Map<string, Set<Handler>>();
const dropHandlers = new Set<(ev: { payload: unknown }) => void>();

declare global {
  interface Window {
    svxEmit(name: string, payload: unknown): void;
    svxDrop(paths: string[]): void;
  }
}

window.svxEmit = (name, payload) => {
  for (const h of listeners.get(name) ?? []) h({ payload });
};
window.svxDrop = (paths) => {
  for (const h of dropHandlers) h({ payload: { type: "drop", paths, position: { x: 0, y: 0 } } });
};

// @tauri-apps/api/core
export async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return (await host.svxMock(cmd, args, frame)) as T;
}

// @tauri-apps/api/event
export async function listen<T>(name: string, handler: (e: { payload: T }) => void): Promise<() => void> {
  const set = listeners.get(name) ?? new Set();
  set.add(handler as Handler);
  listeners.set(name, set);
  return () => set.delete(handler as Handler);
}

// @tauri-apps/api/webview
export function getCurrentWebview() {
  return {
    async onDragDropEvent(h: (ev: { payload: unknown }) => void) {
      dropHandlers.add(h);
      return () => dropHandlers.delete(h);
    },
  };
}

// @tauri-apps/api/app
export async function getVersion(): Promise<string> {
  return "0.1.8";
}
