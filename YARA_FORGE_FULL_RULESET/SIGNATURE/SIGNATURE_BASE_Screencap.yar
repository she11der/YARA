rule SIGNATURE_BASE_Screencap
{
	meta:
		description = "Webshells Auto-generated - file screencap.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "0c1b71d3-ad54-5230-b1ab-971647e76139"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8636-L8649"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "51139091dea7a9418a50f2712ea72aa6"
		logic_hash = "9be7ec97ef8e9b8838f7931a8fcf8d85b1543a202a7bf34fab9791fc47889cb9"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "GetDIBColorTable"
		$s1 = "Screen.bmp"
		$s2 = "CreateDCA"

	condition:
		all of them
}
