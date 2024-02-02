rule BINARYALERT_Ransomware_Windows_Cerber_Evasion
{
	meta:
		description = "Cerber Ransomware: Evades detection by machine learning applications"
		author = "@fusionrace"
		id = "6e2f44a9-bc0f-5071-9d80-ddfb778cfe5d"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "http://www.darkreading.com/vulnerabilities---threats/cerber-ransomware-now-evades-machine-learning/d/d-id/1328506"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/ransomware/windows/ransomware_windows_cerber_evasion.yara#L1-L15"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		hash = "bc62b557d48f3501c383f25d014f22df"
		logic_hash = "43b3b8be5a23b57f6c671abd8491cdc51af1cf3a3fe8a7be308150697cdb92ea"
		score = 75
		quality = 80
		tags = ""

	strings:
		$s1 = "38oDr5.vbs" fullword ascii wide
		$s2 = "8ivq.dll" fullword ascii wide
		$s3 = "jmsctls_progress32" fullword ascii wide

	condition:
		all of them
}