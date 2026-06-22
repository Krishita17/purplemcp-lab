"""Live-data MCP server — real weather + crypto prices, no API key required.

Both tools make genuine HTTPS calls to free, keyless public APIs:

* **weather()**  -> Open-Meteo (geocoding + current weather), https://open-meteo.com
* **crypto_price()** -> CoinGecko simple price, https://www.coingecko.com/en/api

There is nothing mocked here — pull the plug on your network and these error out,
exactly as a real integration should. Use it to demo live tool calls in Chat.

Run directly:  python servers/live_data/server.py
"""

from __future__ import annotations

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "live_data",
    instructions="Real weather and crypto prices from free, keyless public APIs.",
    log_level="WARNING",
)

_GEO = "https://geocoding-api.open-meteo.com/v1/search"
_FORECAST = "https://api.open-meteo.com/v1/forecast"
_COINGECKO = "https://api.coingecko.com/api/v3/simple/price"
_TIMEOUT = 10.0


@mcp.tool()
def weather(city: str) -> str:
    """Current weather for a city name, via the free Open-Meteo API (no key)."""
    with httpx.Client(timeout=_TIMEOUT) as client:
        geo = client.get(_GEO, params={"name": city, "count": 1}).json()
        results = geo.get("results") or []
        if not results:
            return f"No location found for {city!r}."
        place = results[0]
        lat, lon = place["latitude"], place["longitude"]
        wx = client.get(
            _FORECAST,
            params={"latitude": lat, "longitude": lon, "current_weather": True},
        ).json()
        cur = wx.get("current_weather") or {}
    name = ", ".join(p for p in (place.get("name"), place.get("country")) if p)
    return (
        f"{name}: {cur.get('temperature', '?')}°C, "
        f"wind {cur.get('windspeed', '?')} km/h "
        f"(lat {lat:.2f}, lon {lon:.2f})."
    )


@mcp.tool()
def crypto_price(symbol: str = "bitcoin", vs_currency: str = "usd") -> str:
    """Spot price of a coin (CoinGecko id, e.g. 'bitcoin') via the free API (no key)."""
    with httpx.Client(timeout=_TIMEOUT) as client:
        data = client.get(
            _COINGECKO,
            params={"ids": symbol.lower(), "vs_currencies": vs_currency.lower()},
        ).json()
    entry = data.get(symbol.lower())
    if not entry:
        return f"Unknown coin id {symbol!r} (try 'bitcoin', 'ethereum', 'solana')."
    price = entry.get(vs_currency.lower())
    return f"{symbol.lower()} = {price} {vs_currency.upper()}"


if __name__ == "__main__":
    mcp.run()
