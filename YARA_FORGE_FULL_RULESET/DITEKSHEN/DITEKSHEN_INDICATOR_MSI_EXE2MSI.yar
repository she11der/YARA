import "pe"

rule DITEKSHEN_INDICATOR_MSI_EXE2MSI : FILE
{
	meta:
		description = "Detects executables converted to .MSI packages using a free online converter."
		author = "ditekSHen"
		id = "039df7b6-e4bf-5537-ae5b-f2168044e77e"
		date = "2023-08-29"
		modified = "2023-08-29"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_packed.yar#L222-L233"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "afd48b54766600805ae1aeef13b11de4ca160ea1f96419a4090ab9dae55fa4cd"
		score = 75
		quality = 75
		tags = "FILE"
		snort2_sid = "930061-930063"
		snort3_sid = "930022"
		importance = 20

	strings:
		$winin = "Windows Installer" ascii
		$title = "Exe to msi converter free" ascii

	condition:
		uint32(0)==0xe011cfd0 and ($winin and $title)
}
