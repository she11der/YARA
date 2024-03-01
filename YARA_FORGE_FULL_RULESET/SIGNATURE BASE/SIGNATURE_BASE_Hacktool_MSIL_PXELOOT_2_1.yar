import "pe"

rule SIGNATURE_BASE_Hacktool_MSIL_PXELOOT_2_1 : FILE
{
	meta:
		description = "This rule looks for .NET PE files that have the strings of various method names in the PXE And Loot code."
		author = "FireEye"
		id = "ff46a0e9-f7d2-57f2-9727-26b69ea5ba71"
		date = "2020-12-08"
		modified = "2023-01-27"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_fireeye_redteam_tools.yar#L2088-L2113"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d93100fe60c342e9e3b13150fd91c7d8"
		logic_hash = "f9a9167b806e0e3df3720c13b4009e18c5a36913d255978cb001c2284533ea82"
		score = 75
		quality = 43
		tags = "FILE"

	strings:
		$msil = "_CorExeMain" ascii wide
		$str2 = "InvestigateRPC" ascii nocase wide
		$str3 = "DhcpRecon" ascii nocase wide
		$str4 = "UnMountWim" ascii nocase wide
		$str5 = "remote WIM image" ascii nocase wide
		$str6 = "DISMWrapper" ascii nocase wide
		$str7 = "findTFTPServer" ascii nocase wide
		$str8 = "DHCPRequestRecon" ascii nocase wide
		$str9 = "DHCPDiscoverRecon" ascii nocase wide
		$str10 = "GoodieFile" ascii nocase wide
		$str11 = "InfoStore" ascii nocase wide
		$str12 = "execute" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $msil and all of ($str*)
}
