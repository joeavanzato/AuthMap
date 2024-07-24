<h1 align="center">
AuthMap
</h1>

### What is it?
A PowerShell script that helps blue-teamers aggregate Windows authentication activity from across an Active Directory network.

### How does it work?

AuthMap dynamically builds a PowerShell script that is launched on remote computers using Windows Management Instrumentation (WMI).  The script builds a CSV locally on all target devices - after launching all remote jobs, AuthMap continuously loops through reachable devices to check if the output exists via SMB, copying it back to the local computer and removing it from the remote destination.

After all outputs are collected, AuthMap merges individual device results into a single aggregated CSV of data for easy analysis.

### How do I use it?

