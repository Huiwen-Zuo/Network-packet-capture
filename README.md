# Network Packet Capture Tool

This is a C-based packet capture tool that allows users to select a network interface, apply filters (such as HTTP or TCP), capture packets for a specified time period, and save the captured packets to a file.

## Features
- Choose network interface
- Capture all traffic, HTTP only, or TCP only
- Save captured packets to a file with timestamps
- Filters based on user selection

## How to Run
- Run the executable file
- Choose the network interface
- Set capture time in milliseconds
- Choose the filter (All, HTTP, or TCP)

## Requirements
- Npcap installed on your machine
- Winsock library linked in your development environment