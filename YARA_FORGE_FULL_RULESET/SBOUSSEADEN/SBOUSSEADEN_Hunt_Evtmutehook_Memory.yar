rule SBOUSSEADEN_Hunt_Evtmutehook_Memory
{
	meta:
		description = "memory hunt for default wevtsv EtwEventCallback hook pattern to apply to eventlog svchost memory dump"
		author = "SBousseaden"
		id = "5326581e-90d9-59b9-8dc5-74df97571600"
		date = "2020-09-05"
		modified = "2020-09-05"
		reference = "https://blog.dylan.codes/pwning-windows-event-logging/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_memory_evtmutehook.yara#L1-L11"
		license_url = "N/A"
		logic_hash = "3db66069ed67d90031a6fe071dad4d0200ddd661b263dd2860df026673031e48"
		score = 50
		quality = 75
		tags = ""

	strings:
		$a = {49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF E3 54 24 20 4C 8B 05 61 CB 1A 00 0F 57 C0 66 0F 7F 44 24 20 E8 5B 0A 00 00 48 83 C4 38 C3}
		$b = {48 83 EC 38 4C 8B 0D 65 CB 1A 00 48 8D 54 24 20 4C 8B 05 61 CB 1A 00 0F 57 C0 66 0F 7F 44 24 20 E8 5B 0A 00 00 48 83 C4 38 C3}

	condition:
		$a and not $b
}
