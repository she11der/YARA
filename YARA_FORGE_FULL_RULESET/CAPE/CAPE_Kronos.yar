rule CAPE_Kronos : FILE
{
	meta:
		description = "Kronos Payload"
		author = "kevoreilly"
		id = "921a939b-a037-5973-bd8e-f9f55fce7f0f"
		date = "2020-07-02"
		modified = "2020-07-02"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/Kronos.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		logic_hash = "52ce9caf3627efe8ae86df6ca59e51e9f738e13ac0265f797e8d70123dbcaeb3"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Kronos Payload"

	strings:
		$a1 = "user_pref(\"network.cookie.cookieBehavior\""
		$a2 = "T0E0H4U0X3A3D4D8"
		$a3 = "wow64cpu.dll" wide
		$a4 = "Kronos" fullword ascii wide

	condition:
		uint16(0)==0x5A4D and (2 of ($a*))
}
