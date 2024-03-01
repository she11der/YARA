rule SIGNATURE_BASE_Blackenergy3_Installer
{
	meta:
		description = "Matches unique code block for import name construction "
		author = "Mike Schladt"
		id = "4afeb7ac-ce8d-506c-9c97-db7ec6102490"
		date = "2015-05-29"
		modified = "2023-12-05"
		reference = "https://www.f-secure.com/documents/996508/1030745/blackenergy_whitepaper.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_blackenergy_installer.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "78387651dd9608fcdf6bfb9df8b84db4"
		hash = "78636f7bbd52ea80d79b4e2a7882403092bbb02d"
		logic_hash = "c4c562124427fd394b56e48f16f2d262c8a717fc750b955b2b2a35acb478d5e7"
		score = 75
		quality = 85
		tags = ""

	strings:
		$import_names = { C7 45 D0 75 73 65 72 C7 45 D4 33 32 2E 64 66 C7 45 D8 6C 6C 88 5D DA C7 45 84 61 64 76 61 C7 45 88 70 69 33 32 C7 45 8C 2E 64 6C 6C 88 5D 90 C7 45 B8 77 69 6E 69 C7 45 BC 6E 65 74 2E C7 45 C0 64 6C 6C 00 C7 45 C4 77 73 32 5F C7 45 C8 33 32 2E 64 66 C7 45 CC 6C 6C 88 5D CE C7 45 94 73 68 65 6C C7 45 98 6C 33 32 2E C7 45 9C 64 6C 6C 00 C7 45 E8 70 73 61 70 C7 45 EC 69 2E 64 6C 66 C7 45 F0 6C 00 C7 85 74 FF FF FF 6E 65 74 61 C7 85 78 FF FF FF 70 69 33 32 C7 85 7C FF FF FF 2E 64 6C 6C 88 5D 80 C7 85 64 FF FF FF 6F 6C 65 61 C7 85 68 FF FF FF 75 74 33 32 C7 85 6C FF FF FF 2E 64 6C 6C 88 9D 70 FF FF FF C7 45 DC 6F 6C 65 33 C7 45 E0 32 2E 64 6C 66 C7 45 E4 6C 00 C7 45 A0 76 65 72 73 C7 45 A4 69 6F 6E 2E C7 45 A8 64 6C 6C 00 C7 85 54 FF FF FF 69 6D 61 67 C7 85 58 FF FF FF 65 68 6C 70 C7 85 5C FF FF FF 2E 64 6C 6C 88 9D 60 FF FF FF C7 45 AC 61 70 70 68 C7 45 B0 65 6C 70 2E C7 45 B4 64 6C 6C 00 C7 45 F4 2E 64 6C 6C 88 5D F8 }

	condition:
		any of them
}
