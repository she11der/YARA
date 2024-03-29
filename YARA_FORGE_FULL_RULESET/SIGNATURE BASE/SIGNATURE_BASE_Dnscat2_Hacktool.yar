import "pe"

rule SIGNATURE_BASE_Dnscat2_Hacktool : FILE
{
	meta:
		description = "Detects dnscat2 - from files dnscat, dnscat2.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "23cca0fe-3e4e-5b91-8b53-933de8ff264a"
		date = "2016-05-15"
		modified = "2023-12-05"
		reference = "https://downloads.skullsecurity.org/dnscat2/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3244-L3263"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c163a62b607323e08ca083a7091585550c830827728a8a60e25af8db6550ed1c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "8bc8d6c735937c9c040cbbdcfc15f17720a7ecef202a19a7bf43e9e1c66fe66a"
		hash2 = "4a882f013419695c8c0ac41d8a0fde1cf48172a89e342c504138bc6f1d13c7c8"

	strings:
		$s1 = "--exec -e <process>     Execute the given process and link it to the stream." fullword ascii
		$s2 = "Sawlog" fullword ascii
		$s3 = "COMMAND_EXEC [request] :: request_id: 0x%04x :: name: %s :: command: %s" fullword ascii
		$s4 = "COMMAND_SHELL [request] :: request_id: 0x%04x :: name: %s" fullword ascii
		$s5 = "[Tunnel %d] connection to %s:%d closed by the server!" fullword ascii

	condition:
		(( uint16(0)==0x457f or uint16(0)==0x5a4d) and filesize <400KB and (2 of ($s*))) or ( all of them )
}
