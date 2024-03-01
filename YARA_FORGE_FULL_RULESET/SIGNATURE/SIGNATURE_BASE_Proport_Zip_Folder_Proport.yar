import "pe"

rule SIGNATURE_BASE_Proport_Zip_Folder_Proport
{
	meta:
		description = "Auto-generated rule on file ProPort.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "cd611f6c-42ed-5cd3-a6ab-7e0970925e61"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L377-L394"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c1937a86939d4d12d10fc44b7ab9ab27"
		logic_hash = "0ee2ffc5ed243d170b8013b3a164a3719f43bd473f4af7e1a2697d88a298fe9f"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Corrupt Data!"
		$s1 = "K4p~omkIz"
		$s2 = "DllTrojanScan"
		$s3 = "GetDllInfo"
		$s4 = "Compressed by Petite (c)1999 Ian Luck."
		$s5 = "GetFileCRC32"
		$s6 = "GetTrojanNumber"
		$s7 = "TFAKAbout"

	condition:
		all of them
}
