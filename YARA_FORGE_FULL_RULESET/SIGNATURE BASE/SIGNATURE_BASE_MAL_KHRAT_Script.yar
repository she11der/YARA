import "pe"

rule SIGNATURE_BASE_MAL_KHRAT_Script
{
	meta:
		description = "Rule derived from KHRAT script but can match on other malicious scripts as well"
		author = "Florian Roth (Nextron Systems)"
		id = "fd345647-4887-560e-a6b2-129a880026aa"
		date = "2017-08-31"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2017/08/unit42-updated-khrat-malware-used-in-cambodia-attacks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_khrat.yar#L26-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c27a89028794b50b95850d90ee29b56606e6b58b862a26e287077e7f7be7f096"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8c88b4177b59f4cac820b0019bcc7f6d3d50ce4badb689759ab0966780ae32e3"

	strings:
		$x1 = "CreateObject(\"WScript.Shell\").Run \"schtasks /create /sc MINUTE /tn" ascii
		$x2 = "CreateObject(\"WScript.Shell\").Run \"rundll32.exe javascript:\"\"\\..\\mshtml,RunHTMLApplication" ascii
		$x3 = "<registration progid=\"ff010f\" classid=\"{e934870c-b429-4d0d-acf1-eef338b92c4b}\" >" fullword ascii

	condition:
		1 of them
}
