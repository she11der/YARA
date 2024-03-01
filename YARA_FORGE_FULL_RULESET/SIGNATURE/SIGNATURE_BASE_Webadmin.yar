rule SIGNATURE_BASE_Webadmin
{
	meta:
		description = "Webshells Auto-generated - file webadmin.php"
		author = "Florian Roth (Nextron Systems)"
		id = "615d87f8-9094-5994-aea1-d7276623fbca"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8237-L8248"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3a90de401b30e5b590362ba2dde30937"
		logic_hash = "6e215c3d8b8357b839416ee6951f7739387bb94aa1284ea7e827ae2205221294"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<input name=\\\"editfilename\\\" type=\\\"text\\\" class=\\\"style1\\\" value='\".$this->inpu"

	condition:
		all of them
}
