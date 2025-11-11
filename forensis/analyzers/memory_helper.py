from typing import List, Dict

DEFAULT_FOCUS = ["processes", "network", "persistence"]

PROFILE_COMMANDS = {
    "windows.generic": {
        "tool": "volatility3",
        "commands": {
            "processes": [
                "vol -f MEMORY.raw windows.pslist",
                "vol -f MEMORY.raw windows.psscan",
            ],
            "network": [
                "vol -f MEMORY.raw windows.netscan",
            ],
            "persistence": [
                "vol -f MEMORY.raw windows.autoruns",
                "vol -f MEMORY.raw windows.svcscan",
            ],
            "malware": [
                "vol -f MEMORY.raw windows.malfind",
                "vol -f MEMORY.raw windows.driverscan",
            ],
        },
    },
    "linux.generic": {
        "tool": "volatility3",
        "commands": {
            "processes": [
                "vol -f MEMORY.raw linux.pslist",
                "vol -f MEMORY.raw linux.psscan",
            ],
            "network": [
                "vol -f MEMORY.raw linux.netstat",
            ],
            "persistence": [
                "vol -f MEMORY.raw linux.lsmod",
            ],
            "malware": [
                "vol -f MEMORY.raw linux.malfind",
            ],
        },
    },
}

SUSPICIOUS_PROCESS_KEYWORDS = [
    "mimikatz",
    "powershell",
    "cmd.exe",
    "nc.exe",
    "ncat",
    "cobalt",
    "meterpreter",
    "beacon",
    "svch0st",
]

def generate_playbook(profile: str, focus: List[str]):
    profile_data = PROFILE_COMMANDS.get(profile, PROFILE_COMMANDS["windows.generic"])
    tool = profile_data["tool"]
    commands_by_focus = profile_data["commands"]

    selected_focus = focus or DEFAULT_FOCUS
    play_steps = []

    for f in selected_focus:
        cmds = commands_by_focus.get(f)
        if not cmds:
            continue
        play_steps.append(
            {
                "focus": f,
                "description": f"Run {tool} plugins for {f}",
                "commands": cmds,
            }
        )

    events = []
    for f in selected_focus:
        events.append(
            {
                "source": "memory_playbook",
                "category": f,
                "tool": tool,
                "profile": profile,
                "message": f"Memory analysis step for {f} using {tool} ({profile})",
            }
        )

    return {
        "profile": profile,
        "tool": tool,
        "steps": play_steps,
        "events": events,
    }

def analyze_memory_output(raw_output: str) -> Dict:
    lines = [l for l in raw_output.splitlines() if l.strip()]
    suspicious = []
    events = []

    for line in lines:
        lower = line.lower()
        for kw in SUSPICIOUS_PROCESS_KEYWORDS:
            if kw in lower:
                suspicious.append(
                    {
                        "keyword": kw,
                        "line": line.strip(),
                    }
                )
                events.append(
                    {
                        "source": "memory_output",
                        "indicator": kw,
                        "message": line.strip(),
                    }
                )
                break

    summary = {
        "total_lines": len(lines),
        "suspicious_hits": len(suspicious),
    }

    return {
        "summary": summary,
        "suspicious": suspicious,
        "events": events,
    }
