import "pe"

rule SIGNATURE_BASE_MAL_Janicab_LNK
{
	meta:
		description = "detect LNK files used in Janicab infection chain"
		author = "Greg Lesnewich"
		id = "c21844d3-eeee-530e-a69c-b7f604616f0b"
		date = "2023-01-01"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_100days_of_yara_2023.yar#L46-L68"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "0c7e8427ee61672568983e51bf03e0bcf6f2e9c01d2524d82677b20264b23a3f"
		hash = "22ede766fba7551ad0b71ef568d0e5022378eadbdff55c4a02b42e63fcb3b17c"
		hash = "4920e6506ca557d486e6785cb5f7e4b0f4505709ffe8c30070909b040d3c3840"
		hash = "880607cc2da4c3213ea687dabd7707736a879cc5f2f1d4accf79821e4d24d870"
		hash = "f4610b65eba977b3d13eba5da0e38788a9e796a3e9775dd2b8e37b3085c2e1af"
		logic_hash = "f9c000ffb6a95d616459e00f0220ad26cb1df77e35582d14dfce1637ddfb466c"
		score = 75
		quality = 85
		tags = ""
		version = "1.0"
		DaysofYARA = "1/100"

	strings:
		$j_pdf1 = "%PDF-1.5" ascii wide
		$j_cmd = "\\Windows\\System32\\cmd.exe" ascii wide
		$j_pdf_stream = "endstream" ascii wide
		$j_pdb_obj = "endobj" ascii wide
		$dimensions = {02 00 00 A0 ?? 00 ?? ?? 01 00 01 00 01}

	condition:
		uint32be(0x0)==0x4C000000 and $dimensions and 2 of ($j_*)
}
