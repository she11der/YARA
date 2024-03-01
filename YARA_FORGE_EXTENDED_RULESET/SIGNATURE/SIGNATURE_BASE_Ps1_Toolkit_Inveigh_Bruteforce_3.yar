rule SIGNATURE_BASE_Ps1_Toolkit_Inveigh_Bruteforce_3 : FILE
{
	meta:
		description = "Auto-generated rule - from files Inveigh-BruteForce.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "d284e93b-dd65-5a39-84e2-287feb6ae05b"
		date = "2016-09-04"
		modified = "2023-12-05"
		reference = "https://github.com/vysec/ps1-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_powershell_toolkit.yar#L228-L248"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "09afe669e90bd73318a9f9f68fda362451f6611f8585de67176c5dc43f05f937"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash3 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"

	strings:
		$s1 = "::FromBase64String('TgBUAEwATQA=')" ascii
		$s2 = "::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))" ascii
		$s3 = "::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))" ascii
		$s4 = "::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))" ascii
		$s5 = "[Byte[]] $HTTP_response = (0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20)`" fullword ascii
		$s6 = "KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA" ascii
		$s7 = "}.bruteforce_running)" ascii

	condition:
		( uint16(0)==0xbbef and filesize <200KB and 2 of them ) or (4 of them )
}
