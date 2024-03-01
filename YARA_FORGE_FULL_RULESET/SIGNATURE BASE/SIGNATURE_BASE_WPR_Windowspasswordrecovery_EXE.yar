import "pe"

rule SIGNATURE_BASE_WPR_Windowspasswordrecovery_EXE : FILE
{
	meta:
		description = "Windows Password Recovery - file wpr.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "7fa2062c-75dd-55aa-8775-631a9c1a497e"
		date = "2017-03-15"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3574-L3603"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0f2995a8ba1644d384167221560aa0c3f074e8e2cf2b79bbb06537fcaed2df7f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c1c64cba5c8e14a1ab8e9dd28828d036581584e66ed111455d6b4737fb807783"

	strings:
		$x1 = "UuPipe" fullword ascii
		$x2 = "dbadllgl" fullword ascii
		$x3 = "UkVHSVNUUlkgTU9O" fullword ascii
		$x4 = "RklMRSBNT05JVE9SIC0gU1l" fullword ascii
		$s1 = "WPR.exe" fullword wide
		$s2 = "Windows Password Recovery" fullword wide
		$op0 = { 5f df 27 17 89 }
		$op1 = { 5f 00 00 f2 e5 cb 97 }
		$op2 = { e8 ed 00 f0 cc e4 00 a0 17 }

	condition:
		uint16(0)==0x5a4d and filesize <20000KB and (1 of ($x*) or all of ($s*) or all of ($op*))
}
