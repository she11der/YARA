import "pe"

rule SIGNATURE_BASE_Hacktools_CN_Johor_Posts_Killer
{
	meta:
		description = "Disclosed hacktool set - file JoHor_Posts_Killer.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "68bba78e-f3a0-5eaa-9c63-e5f23a76b328"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1300-L1321"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d157f9a76f9d72dba020887d7b861a05f2e56b6a"
		logic_hash = "2fc63cd42619a2b92ab8670b14ab4c01eb3b194cd337d329ba224b7088d26318"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Multithreading Posts_Send Killer" fullword ascii
		$s3 = "GET [Access Point] HTTP/1.1" fullword ascii
		$s6 = "The program's need files was not exist!" fullword ascii
		$s7 = "JoHor_Posts_Killer" fullword wide
		$s8 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
		$s10 = "  ( /s ) :" fullword ascii
		$s11 = "forms.vbp" fullword ascii
		$s12 = "forms.vcp" fullword ascii
		$s13 = "Software\\FlySky\\E\\Install" fullword ascii

	condition:
		5 of them
}
