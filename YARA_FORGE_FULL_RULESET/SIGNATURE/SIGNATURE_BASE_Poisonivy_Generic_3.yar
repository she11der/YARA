rule SIGNATURE_BASE_Poisonivy_Generic_3 : FILE
{
	meta:
		description = "PoisonIvy RAT Generic Rule"
		author = "Florian Roth (Nextron Systems)"
		id = "0f6a47ee-b741-59cc-b2d6-6bf3989ce8e7"
		date = "2015-05-14"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_poisonivy_gen3.yar#L2-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e1cbdf740785f97c93a0a7a01ef2614be792afcd"
		logic_hash = "8116b07c00218a0e9784447f322455ff24ae754770b85db760b1c397e10e5695"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$k1 = "Tiger324{" fullword ascii
		$s2 = "WININET.dll" fullword ascii
		$s3 = "mscoree.dll" fullword wide
		$s4 = "WS2_32.dll" fullword
		$s5 = "Explorer.exe" fullword wide
		$s6 = "USER32.DLL"
		$s7 = "CONOUT$"
		$s8 = "login.asp"
		$h1 = "HTTP/1.0"
		$h2 = "POST"
		$h3 = "login.asp"
		$h4 = "check.asp"
		$h5 = "result.asp"
		$h6 = "upload.asp"

	condition:
		uint16(0)==0x5a4d and filesize <500KB and ($k1 or all of ($s*) or all of ($h*))
}
