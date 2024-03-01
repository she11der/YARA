rule SIGNATURE_BASE_Blackenergy_BE_2 : FILE
{
	meta:
		description = "Detects BlackEnergy 2 Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "c93991b9-77e8-5a73-80ef-e21df770c3a5"
		date = "2015-02-19"
		modified = "2023-12-05"
		reference = "http://goo.gl/DThzLz"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_blackenergy.yar#L8-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "983cfcf3aaaeff1ad82eb70f77088ad6ccedee77"
		logic_hash = "77ecab353063bf8be5ec70294f8497234af8ddd944e0b207d8d633f59f76dbb6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<description> Windows system utility service  </description>" fullword ascii
		$s1 = "WindowsSysUtility - Unicode" fullword wide
		$s2 = "msiexec.exe" fullword wide
		$s3 = "WinHelpW" fullword ascii
		$s4 = "ReadProcessMemory" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <250KB and all of ($s*)
}
