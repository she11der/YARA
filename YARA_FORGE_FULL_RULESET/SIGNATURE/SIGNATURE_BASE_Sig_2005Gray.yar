rule SIGNATURE_BASE_Sig_2005Gray
{
	meta:
		description = "Webshells Auto-generated - file 2005Gray.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "978fb04e-517d-51cf-98ca-5fd6b421365e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L7608-L7622"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "75dbe3d3b70a5678225d3e2d78b604cc"
		logic_hash = "927ed5cdaa14b6cd63a6ca7d7bec6635b69fa19d88808890e7d198fb7a0b57b4"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "SCROLLBAR-FACE-COLOR: #e8e7e7;"
		$s4 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
		$s8 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
		$s9 = "SCROLLBAR-3DLIGHT-COLOR: #cccccc;"

	condition:
		all of them
}
