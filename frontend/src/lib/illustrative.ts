import type { GlobeArc, GlobeNode } from "@/components/globe/GlobeView";

interface City {
  name: string;
  country: string;
  lat: number;
  lng: number;
}

export const cities: Record<string, City> = {
  amsterdam: { name: "Amsterdam", country: "NL", lat: 52.37, lng: 4.9 },
  frankfurt: { name: "Frankfurt", country: "DE", lat: 50.11, lng: 8.68 },
  london: { name: "London", country: "GB", lat: 51.51, lng: -0.13 },
  paris: { name: "Paris", country: "FR", lat: 48.86, lng: 2.35 },
  madrid: { name: "Madrid", country: "ES", lat: 40.42, lng: -3.7 },
  stockholm: { name: "Stockholm", country: "SE", lat: 59.33, lng: 18.07 },
  virginia: { name: "Ashburn", country: "US", lat: 39.04, lng: -77.49 },
  sanfrancisco: { name: "San Francisco", country: "US", lat: 37.77, lng: -122.42 },
  saopaulo: { name: "São Paulo", country: "BR", lat: -23.55, lng: -46.63 },
  lagos: { name: "Lagos", country: "NG", lat: 6.52, lng: 3.38 },
  dubai: { name: "Dubai", country: "AE", lat: 25.2, lng: 55.27 },
  mumbai: { name: "Mumbai", country: "IN", lat: 19.08, lng: 72.88 },
  singapore: { name: "Singapore", country: "SG", lat: 1.35, lng: 103.82 },
  tokyo: { name: "Tokyo", country: "JP", lat: 35.68, lng: 139.69 },
  sydney: { name: "Sydney", country: "AU", lat: -33.87, lng: 151.21 },
  seoul: { name: "Seoul", country: "KR", lat: 37.57, lng: 126.98 },
};

const hub = cities.frankfurt;

const routes: { from: City; to: City; severity: string; count: number }[] = [
  { from: cities.virginia, to: hub, severity: "critical", count: 4180 },
  { from: cities.singapore, to: hub, severity: "high", count: 2610 },
  { from: cities.saopaulo, to: hub, severity: "medium", count: 1540 },
  { from: cities.mumbai, to: cities.london, severity: "high", count: 1980 },
  { from: cities.tokyo, to: cities.amsterdam, severity: "medium", count: 1290 },
  { from: cities.lagos, to: cities.paris, severity: "critical", count: 990 },
  { from: cities.sydney, to: cities.singapore, severity: "low", count: 860 },
  { from: cities.seoul, to: cities.sanfrancisco, severity: "medium", count: 1120 },
  { from: cities.dubai, to: cities.frankfurt, severity: "low", count: 720 },
  { from: cities.stockholm, to: cities.london, severity: "low", count: 640 },
  { from: cities.madrid, to: cities.virginia, severity: "medium", count: 580 },
  { from: cities.sanfrancisco, to: cities.tokyo, severity: "low", count: 540 },
  { from: cities.london, to: cities.virginia, severity: "high", count: 1480 },
  { from: cities.paris, to: cities.singapore, severity: "low", count: 460 },
];

export const heroNodes: GlobeNode[] = [
  { ...hub, country: "DE", volume: 42_000, connections: 9840, severity: "critical" },
  { ...cities.virginia, country: "US", volume: 28_000, connections: 6410, severity: "critical" },
  { ...cities.singapore, country: "SG", volume: 19_000, connections: 4380, severity: "high" },
  { ...cities.london, country: "GB", volume: 16_000, connections: 3920, severity: "high" },
  { ...cities.mumbai, country: "IN", volume: 12_000, connections: 2810, severity: "high" },
  { ...cities.tokyo, country: "JP", volume: 9_400, connections: 2140, severity: "medium" },
  { ...cities.saopaulo, country: "BR", volume: 7_800, connections: 1760, severity: "medium" },
  { ...cities.sanfrancisco, country: "US", volume: 7_100, connections: 1650, severity: "medium" },
  { ...cities.dubai, country: "AE", volume: 5_600, connections: 1180, severity: "low" },
  { ...cities.lagos, country: "NG", volume: 4_900, connections: 960, severity: "critical" },
  { ...cities.sydney, country: "AU", volume: 3_800, connections: 820, severity: "low" },
  { ...cities.stockholm, country: "SE", volume: 3_100, connections: 720, severity: "low" },
  { ...cities.paris, country: "FR", volume: 2_900, connections: 690, severity: "medium" },
  { ...cities.madrid, country: "ES", volume: 2_400, connections: 560, severity: "medium" },
  { ...cities.seoul, country: "KR", volume: 2_200, connections: 510, severity: "medium" },
  { ...cities.amsterdam, country: "NL", volume: 2_000, connections: 470, severity: "medium" },
];

export const heroArcs: GlobeArc[] = routes.map((route) => ({
  startLat: route.from.lat,
  startLng: route.from.lng,
  endLat: route.to.lat,
  endLng: route.to.lng,
  srcCity: route.from.name,
  dstCity: route.to.name,
  srcCountry: route.from.country,
  dstCountry: route.to.country,
  count: route.count,
  bytes: route.count * 1_450_000,
  severity: route.severity,
}));
