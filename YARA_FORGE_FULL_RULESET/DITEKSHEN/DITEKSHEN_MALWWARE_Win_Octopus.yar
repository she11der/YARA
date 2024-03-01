import "pe"

rule DITEKSHEN_MALWWARE_Win_Octopus : FILE
{
	meta:
		description = "Detects Octopus trojan payload"
		author = "ditekSHen"
		id = "eb092e23-864f-52f3-bfa4-7e3c616d3984"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/malware.yar#L2894-L2917"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "012b75c94be3021dbcc5b8e8bd62f807c9aa8bc0df94f830a5294aaf0d21b9fc"
		score = 75
		quality = 23
		tags = "FILE"
		clamav_sig = "MALWARE.Win.Trojan.Octopus"

	strings:
		$s1 = "\\Mozilla\\Firefox\\Profiles\\" fullword wide
		$s2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword wide
		$s3 = "\\wbem\\WMIC.exe" fullword wide
		$s4 = ".profiles.ini" fullword wide
		$s5 = "PushEBP_" ascii
		$s6 = "MovEBP_ESP_" ascii
		$s7 = "Embarcadero Delphi for Win32 compiler" ascii
		$s8 = "TempWmicBatchFile.bat" fullword wide
		$wq1 = "computersystem get Name /format:list" wide
		$wq2 = "os get installdate /format:list" wide
		$wq3 = "get serialnumber /format:list" wide
		$wq4 = "\\\\\\\\.\\\\PHYSICALDRIVE" wide
		$wq5 = "path CIM_LogicalDiskBasedOnPartition" wide
		$wq6 = "get Antecedent,Dependent" wide
		$wq7 = "path win32_physicalmedia" wide

	condition:
		uint16(0)==0x5a4d and (6 of ($s*) and 5 of ($wq*))
}
