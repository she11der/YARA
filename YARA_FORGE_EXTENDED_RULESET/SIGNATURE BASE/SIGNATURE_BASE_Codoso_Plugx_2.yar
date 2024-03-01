rule SIGNATURE_BASE_Codoso_Plugx_2 : FILE
{
	meta:
		description = "Detects Codoso APT PlugX Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "0402a0ff-5664-52db-a739-51c5181853f8"
		date = "2016-01-30"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_codoso.yar#L28-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b9510e4484fa7e3034228337768176fce822162ad819539c6ca3631deac043eb"
		logic_hash = "5ee652a135d4865340d2ce6421144ec76ccc7ab69704e92904b2e2ebfc72edfc"
		score = 75
		quality = 60
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "%TEMP%\\HID" fullword wide
		$s2 = "%s\\hid.dll" fullword wide
		$s3 = "%s\\SOUNDMAN.exe" fullword wide
		$s4 = "\"%s\\SOUNDMAN.exe\" %d %d" fullword wide
		$s5 = "%s\\HID.dllx" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 3 of them ) or all of them
}
