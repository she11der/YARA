rule CAPE_Agentteslav4Jit
{
	meta:
		description = "AgentTesla JIT-compiled native code"
		author = "kevoreilly"
		id = "a87dca44-4974-543c-9565-487ed99be2a6"
		date = "2023-10-31"
		modified = "2023-10-31"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/AgentTesla.yar#L140-L153"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		logic_hash = "8f7144d2a989ce8d291af926b292f5f0f7772e707b0e49797eba13ecf91b90bc"
		score = 75
		quality = 70
		tags = ""
		cape_type = "AgentTesla Payload"
		packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"

	strings:
		$decode1 = {8B 01 8B 40 3C FF 50 10 8B C8 E8 [4] 89 45 CC B8 1A 00 00 00}
		$decode2 = {83 F8 18 75 2? 8B [2-5] D1 F8}
		$decode3 = {8D 4C 0? 08 0F B6 01 [0-3] 0F B6 5? 04 33 C2 88 01 B8 19 00 00 00}

	condition:
		2 of them
}
