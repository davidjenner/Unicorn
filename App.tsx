// src/App.tsx
import { useState } from "react";

export default function App() {
  const [url, setUrl] = useState("");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    setLoading(true);
    const response = await fetch("http://localhost:5000/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await response.json();
    setResults(data);
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white flex flex-col items-center justify-center">
      <h1 className="text-3xl font-bold mb-4">Website Scanner</h1>
      <input
        type="text"
        placeholder="Enter website URL"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        className="p-2 w-80 text-black rounded-lg"
      />
      <button
        onClick={handleScan}
        className="bg-blue-500 text-white p-2 mt-2 rounded-lg"
        disabled={loading}
      >
        {loading ? "Scanning..." : "Scan Website"}
      </button>

      {results && (
        <div className="mt-6 p-4 w-full max-w-2xl bg-gray-800 rounded-lg">
          <h2 className="text-xl font-semibold">Scan Results</h2>
          <pre className="mt-2 p-2 bg-gray-700 rounded-lg">{JSON.stringify(results, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}