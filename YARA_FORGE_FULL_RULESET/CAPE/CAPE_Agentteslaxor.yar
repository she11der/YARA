rule CAPE_Agentteslaxor : FILE
{
	meta:
		description = "AgentTesla xor-based config decoding"
		author = "kevoreilly"
		id = "81eeb62f-578f-5c75-bc96-091d5727a20a"
		date = "2023-10-31"
		modified = "2023-10-31"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/AgentTesla.yar#L113-L123"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		logic_hash = "54581e83e5fa13fae4bda74016b3fa1d18c92e2659f493ebe54d70fd5f77bba5"
		score = 75
		quality = 20
		tags = "FILE"
		cape_type = "AgentTesla Payload"

	strings:
		$decode = {06 91 06 61 20 [4] 61 D2 9C 06 17 58 0A 06 7E [4] 8E 69 FE 04 2D ?? 2A}

	condition:
		uint16(0)==0x5A4D and any of them
}
