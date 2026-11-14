[README.md](https://github.com/user-attachments/files/34857820/README.md)
# Minetest / Luanti Chat Mute Proxy

A small experimental Python 3 UDP proxy for **Luanti (formerly Minetest)**. It lets you hide chat from a selected displayed sender or a Discord relay, and optionally changes incoming chat text colors to white for readability.

No extra Python packages, game modifications, or administrator permissions are required.

## Setup and use

1. Download `minetest_mute_player.py`.
2. Open it in a text editor and change the settings at the top:

   ```python
   player = '@Discord'              # 'Bob', 'Bob@Discord', '@Discord', or '' (mute nobody)
   server = 'example.server.net'    # Replace with your game server address
   server_port = 30000              # Your game server's UDP port
   local_port = 31000               # Port for the local proxy
   force_white_chat = True          # Set to False to keep original chat colors
   ```

3. Run it in a terminal:

   ```bash
   python3 minetest_mute_player.py
   ```

4. In Luanti, connect to **`127.0.0.1`** on port **`31000`** (or the `local_port` you chose), **not** directly to the game server. Keep the Python program running while you play.
5. Press **Ctrl+C** in the terminal to stop the proxy.

## Mute settings

- `player = 'Bob'` — mute displayed sender Bob, including Bob@Discord.
- `player = 'Bob@Discord'` — mute that particular displayed sender/source combination.
- `player = '@Discord'` — mute displayed senders relayed from Discord.
- `player = ''` — don't mute anyone; optional white chat remains available.

## Notes

This is an **experimental, single-client** proxy. It modifies only recognized, unsplit incoming chat packets; other packets pass through. Behavior may vary with Luanti versions and server mods. Sender names are display text, not verified identities. **Do not use this as a security or privacy tool.**

Licensed under the repository's MIT license.
