import "pe"

rule SIGNATURE_BASE_Sig_238_Token
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file token.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "9d0ac24b-2078-5455-8d9e-a642c71f7b2d"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1677-L1694"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c52bc6543d4281aa75a3e6e2da33cfb4b7c34b14"
		logic_hash = "88d7086a48c6a2e3801db75565184b087e663e80e2364765072fc37a5549b8b5"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Logon.exe" fullword ascii
		$s1 = "Domain And User:" fullword ascii
		$s2 = "PID=Get Addr$(): One" fullword ascii
		$s3 = "Process " fullword ascii
		$s4 = "psapi.dllK" fullword ascii

	condition:
		all of them
}
