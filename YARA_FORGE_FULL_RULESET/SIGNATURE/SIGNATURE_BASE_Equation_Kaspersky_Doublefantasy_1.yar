rule SIGNATURE_BASE_Equation_Kaspersky_Doublefantasy_1 : FILE
{
	meta:
		description = "Equation Group Malware - DoubleFantasy"
		author = "Florian Roth (Nextron Systems)"
		id = "f3c87adf-86c3-5d7c-9532-75341841869a"
		date = "2015-02-16"
		modified = "2023-12-05"
		reference = "http://goo.gl/ivt8EW"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L109-L138"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d09b4b6d3244ac382049736ca98d7de0c6787fa2"
		logic_hash = "4471601300616b5442de95a3eb23c28563206f3423b57fe81007d005203a439f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$z1 = "msvcp5%d.dll" fullword ascii
		$s0 = "actxprxy.GetProxyDllInfo" fullword ascii
		$s3 = "actxprxy.DllGetClassObject" fullword ascii
		$s5 = "actxprxy.DllRegisterServer" fullword ascii
		$s6 = "actxprxy.DllUnregisterServer" fullword ascii
		$x2 = "191H1a1" fullword ascii
		$x3 = "November " fullword ascii
		$x4 = "abababababab" fullword ascii
		$x5 = "January " fullword ascii
		$x6 = "October " fullword ascii
		$x7 = "September " fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <350000 and (($z1) or ( all of ($s*) and 6 of ($x*)))
}
