rule SIGNATURE_BASE_Empire_Invoke_Egresscheck : FILE
{
	meta:
		description = "Detects Empire component - file Invoke-EgressCheck.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "21e09250-6853-5743-a6ef-aa6be8091d33"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_empire.yar#L209-L222"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "693564e0bd98ebd03cd433d8ba1003051a5cf6b1f0c05d3c5a4682e6d667327e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e2d270266abe03cfdac66e6fc0598c715e48d6d335adf09a9ed2626445636534"

	strings:
		$s1 = "egress -ip $ip -port $c -delay $delay -protocol $protocol" fullword ascii

	condition:
		( uint16(0)==0x233c and filesize <10KB and 1 of them ) or all of them
}
