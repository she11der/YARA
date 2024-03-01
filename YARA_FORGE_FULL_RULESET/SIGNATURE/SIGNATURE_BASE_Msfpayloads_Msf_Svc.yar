rule SIGNATURE_BASE_Msfpayloads_Msf_Svc : FILE
{
	meta:
		description = "Metasploit Payloads - file msf-svc.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "45d1c527-1f90-50f3-8e64-e77d69386b0a"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_metasploit_payloads.yar#L271-L285"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "21c6aa2333335a5822328fb5176ca37060eb401640ed5cc340aefb63685078f4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2b02c9c10577ee0c7590d3dadc525c494122747a628a7bf714879b8e94ae5ea1"

	strings:
		$s1 = "PAYLOAD:" fullword ascii
		$s2 = ".exehll" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and all of them )
}
