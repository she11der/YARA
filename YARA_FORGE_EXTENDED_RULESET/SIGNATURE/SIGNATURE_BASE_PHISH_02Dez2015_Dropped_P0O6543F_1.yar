rule SIGNATURE_BASE_PHISH_02Dez2015_Dropped_P0O6543F_1 : FILE
{
	meta:
		description = "Phishing Wave - file p0o6543f.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3335ad3c-47f8-5547-bac0-df2d98ff644f"
		date = "2015-12-02"
		modified = "2023-12-05"
		reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_phish_gina_dec15.yar#L8-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "db788d6d3a8ed1a6dc9626852587f475e7671e12fa9c9faa73b7277886f1e210"
		logic_hash = "91fc1b4682c1490b916b11685e1ecc74a964d657e544c0b84e8301b299154d02"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "netsh.exe" fullword wide
		$s2 = "routemon.exe" fullword wide
		$s3 = "script=" fullword wide
		$s4 = "disconnect" fullword wide
		$s5 = "GetClusterResourceTypeKey" fullword ascii
		$s6 = "QueryInformationJobObject" fullword ascii
		$s7 = "interface" fullword wide
		$s8 = "connect" fullword wide
		$s9 = "FreeConsole" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <250KB and all of them
}
