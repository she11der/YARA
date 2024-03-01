rule SIGNATURE_BASE_Rknt_Zip_Folder_Rknt
{
	meta:
		description = "Webshells Auto-generated - file RkNT.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "a58a3b33-8096-535a-b930-2eb71347edb8"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8112-L8129"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5f97386dfde148942b7584aeb6512b85"
		logic_hash = "59de8a40a7081ee5fbea9f413590237c1da9985f2352b32571529baf38c93ddb"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "PathStripPathA"
		$s1 = "`cLGet!Addr%"
		$s2 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
		$s3 = "oQToOemBuff* <="
		$s4 = "ionCdunAsw[Us'"
		$s6 = "CreateProcessW: %S"
		$s7 = "ImageDirectoryEntryToData"

	condition:
		all of them
}
