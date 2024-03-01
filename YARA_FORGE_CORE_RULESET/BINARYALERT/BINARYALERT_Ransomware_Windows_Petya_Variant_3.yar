rule BINARYALERT_Ransomware_Windows_Petya_Variant_3
{
	meta:
		description = "Petya Ransomware new variant June 2017 using ETERNALBLUE"
		author = "@fusionrace"
		id = "cbf06e62-abe8-54af-b4f4-624ba9233e4b"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/ransomware/windows/ransomware_windows_petya_variant_3.yara#L1-L13"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		hash = "71b6a493388e7d0b40c83ce903bc6b04"
		logic_hash = "4f21b394eb2dd0ebf416b018f438934fdc89cb896701d95b593477fc19abfe48"
		score = 75
		quality = 80
		tags = ""

	strings:
		$s1 = "wevtutil cl Setup & wevtutil cl System" fullword wide
		$s2 = "fsutil usn deletejournal /D %c:" fullword wide

	condition:
		any of them
}
