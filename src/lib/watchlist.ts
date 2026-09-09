import { create } from "zustand";
import { persist } from "zustand/middleware";

type WatchState = {
  cves: string[];
  misconfigs: string[];
  toggleCve: (id: string) => void;
  toggleMisconfig: (slug: string) => void;
};

export const useWatchlist = create<WatchState>()(
  persist(
    (set, get) => ({
      cves: [],
      misconfigs: [],
      toggleCve: (id) => {
        const cur = get().cves;
        set({
          cves: cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id],
        });
      },
      toggleMisconfig: (slug) => {
        const cur = get().misconfigs;
        set({
          misconfigs: cur.includes(slug)
            ? cur.filter((x) => x !== slug)
            : [...cur, slug],
        });
      },
    }),
    { name: "nine-watch" },
  ),
);
