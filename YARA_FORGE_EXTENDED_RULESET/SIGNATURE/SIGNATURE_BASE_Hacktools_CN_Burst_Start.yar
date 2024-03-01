import "pe"

rule SIGNATURE_BASE_Hacktools_CN_Burst_Start
{
	meta:
		description = "Disclosed hacktool set - file Start.bat - DoS tool"
		author = "Florian Roth (Nextron Systems)"
		id = "1291fbc5-fbb3-5425-bb9a-e45f4d7cf562"
		date = "2014-11-17"
		modified = "2023-01-27"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1358-L1380"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "75d194d53ccc37a68286d246f2a84af6b070e30c"
		logic_hash = "b435957150da7b790809d2cf90a01c967127c183ddcbf333beda1a7c599b69a5"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "for /f \"eol= tokens=1,2 delims= \" %%i in (ip.txt) do (" ascii
		$s1 = "Blast.bat /r 600" fullword ascii
		$s2 = "Blast.bat /l Blast.bat" fullword ascii
		$s3 = "Blast.bat /c 600" fullword ascii
		$s4 = "start Clear.bat" fullword ascii
		$s5 = "del Result.txt" fullword ascii
		$s6 = "s syn %%i %%j 3306 /save" fullword ascii
		$s7 = "start Thecard.bat" fullword ascii
		$s10 = "setlocal enabledelayedexpansion" fullword ascii

	condition:
		5 of them
}
