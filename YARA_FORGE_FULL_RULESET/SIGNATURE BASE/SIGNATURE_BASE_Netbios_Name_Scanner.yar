import "pe"

rule SIGNATURE_BASE_Netbios_Name_Scanner
{
	meta:
		description = "Auto-generated rule on file NetBIOS Name Scanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "03716e00-a969-5ab5-9be7-e8fc4272e40f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L219-L231"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "888ba1d391e14c0a9c829f5a1964ca2c"
		logic_hash = "19b40a283b74317fece2f5be0ee3e38227d9631eebbc7efb0ea19056b52630f1"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "IconEx"
		$s2 = "soft Visual Stu"
		$s4 = "NBTScanner!y&"

	condition:
		all of them
}
