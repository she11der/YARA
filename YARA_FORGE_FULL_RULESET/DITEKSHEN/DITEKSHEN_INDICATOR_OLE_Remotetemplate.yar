rule DITEKSHEN_INDICATOR_OLE_Remotetemplate
{
	meta:
		description = "Detects XML relations where an OLE object is refrencing an external target in dropper OOXML documents"
		author = "ditekSHen"
		id = "fbf40436-fc0a-5e55-89ac-5e1dd93e1833"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_office.yar#L666-L677"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "80cc5b1a8a8899f632401956055374d265c734449e56ffeee5f0ba4911050f36"
		score = 75
		quality = 75
		tags = ""

	strings:
		$olerel = "relationships/oleObject" ascii
		$target1 = "Target=\"http" ascii
		$target2 = "Target=\"file" ascii
		$mode = "TargetMode=\"External" ascii

	condition:
		$olerel and $mode and 1 of ($target*)
}
