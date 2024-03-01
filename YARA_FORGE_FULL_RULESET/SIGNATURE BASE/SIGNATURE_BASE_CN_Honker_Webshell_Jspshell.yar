rule SIGNATURE_BASE_CN_Honker_Webshell_Jspshell : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jspshell.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "ff72f94b-1c0a-5615-b35f-35f69c920292"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L1083-L1098"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d16af622f7688d4e0856a2678c4064d3d120e14b"
		logic_hash = "9b952f941eb87d7a1b4f747f4e0b0b5ee8876190c6f684b811057a2c78044047"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "else if(Z.equals(\"M\")){String[] c={z1.substring(2),z1.substring(0,2),z2};Proce" ascii
		$s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii

	condition:
		filesize <30KB and all of them
}
