#!/bin/bash
# Ventana flotante del panel — GNOME: zenity --text-info con refresco.
cd "$(dirname "$0")" && exec python3 panel.py --zenity
