import "pe"

rule SIGNATURE_BASE_Hacktools_CN_Panda_445
{
	meta:
		description = "Disclosed hacktool set - file 445.rar"
		author = "Florian Roth (Nextron Systems)"
		id = "02075631-49cc-5b97-ad8e-92d734a26d34"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1149-L1169"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a61316578bcbde66f39d88e7fc113c134b5b966b"
		logic_hash = "d3f5b2c601dfa1702bbd1f8bdc1f847dd34ba84a6c527a3e02cdb76075e4ad2c"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "for /f %%i in (ips.txt) do (start cmd.bat %%i)" fullword ascii
		$s1 = "445\\nc.exe" fullword ascii
		$s2 = "445\\s.exe" fullword ascii
		$s3 = "cs.exe %1" fullword ascii
		$s4 = "445\\cs.exe" fullword ascii
		$s5 = "445\\ip.txt" fullword ascii
		$s6 = "445\\cmd.bat" fullword ascii
		$s9 = "@echo off" fullword ascii

	condition:
		all of them
}
